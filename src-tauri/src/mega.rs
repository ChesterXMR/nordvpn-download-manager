//! mega.nz public file and folder links.
//!
//! Everything on MEGA is encrypted client-side. A link carries the key in its `#fragment`:
//! - `mega.nz/file/<handle>#<key>`: a 32-byte file key.
//! - `mega.nz/folder/<handle>#<key>`: a 16-byte folder key that decrypts the keys of every file
//!   in the folder. `.../folder/<handle>#<key>/file/<file handle>` names one file inside it.
//!
//! A file key yields an AES-128 key and an 8-byte nonce; the file is AES-128-CTR encrypted with
//! counter `nonce || block index`, so any byte range can be decrypted independently and the
//! parallel engine works unchanged. All API calls go through the download's NordVPN client.

use std::time::Duration;

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek},
    Aes128,
};
use anyhow::{anyhow, bail, Result};
use base64::{
    alphabet,
    engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig},
    Engine,
};
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;
use wreq::Client;

use crate::util;

const API: &str = "https://g.api.mega.co.nz/cs";
/// The API asks clients to retry after `EAGAIN`.
const ATTEMPTS: u32 = 4;

const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// A parsed MEGA link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    File { handle: String, key: [u8; 32] },
    Folder { handle: String, key: [u8; 16], file: Option<String> },
}

pub fn is_mega(url: &Url) -> bool {
    url.host_str()
        .is_some_and(|h| matches!(h, "mega.nz" | "mega.co.nz" | "www.mega.nz" | "www.mega.co.nz"))
}

/// Parses new-style (`/file/h#k`, `/folder/h#k[/file/h]`) and legacy (`#!h!k`, `#F!h!k`) links.
pub fn parse(url: &Url) -> Option<Link> {
    if !is_mega(url) {
        return None;
    }
    let fragment = url.fragment().unwrap_or_default();
    let path: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();
    let (kind, handle, rest) = match path.as_slice() {
        [kind @ ("file" | "folder"), handle] => (*kind, handle.to_string(), fragment.to_string()),
        [] if fragment.starts_with("F!") => {
            let mut parts = fragment[2..].splitn(2, '!');
            ("folder", parts.next()?.to_string(), parts.next()?.to_string())
        }
        [] if fragment.starts_with('!') => {
            let mut parts = fragment[1..].splitn(2, '!');
            ("file", parts.next()?.to_string(), parts.next()?.to_string())
        }
        _ => return None,
    };
    if kind == "file" {
        let key = decode(&rest).ok()?.try_into().ok()?;
        return Some(Link::File { handle, key });
    }
    // `<key>/file/<handle>` (or legacy `<key>!<handle>`) selects one file of the folder.
    let (key, file) = match rest.split_once("/file/").or_else(|| rest.split_once('!')) {
        Some((key, file)) => (key, Some(file.trim_matches('/').to_string()).filter(|f| !f.is_empty())),
        None => (rest.as_str(), None),
    };
    let key = decode(key).ok()?.try_into().ok()?;
    Some(Link::Folder { handle, key, file })
}


fn decode(s: &str) -> Result<Vec<u8>> {
    let normalized: String = s.trim().chars().map(|c| match c { '+' => '-', '/' => '_', c => c }).collect();
    B64.decode(normalized.trim_end_matches(',')).map_err(|_| anyhow!("The MEGA link's key is damaged"))
}

fn aes_ecb_decrypt(key: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    for block in data.chunks_exact_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
}

fn aes_cbc_decrypt(key: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = [0u8; 16];
    for block in data.chunks_exact_mut(16) {
        let saved: [u8; 16] = block.try_into().unwrap();
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        block.iter_mut().zip(prev).for_each(|(b, p)| *b ^= p);
        prev = saved;
    }
}

/// Splits a 32-byte file key into the AES key and the CTR nonce.
fn unpack_file_key(k: &[u8; 32]) -> ([u8; 16], [u8; 8]) {
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = k[i] ^ k[i + 16];
    }
    (key, k[16..24].try_into().unwrap())
}

/// Decrypts a node's `MEGA{"n":"name",...}` attributes and returns the name.
fn decrypt_name(attributes: &str, key: &[u8; 16]) -> Option<String> {
    let mut data = decode(attributes).ok()?;
    data.truncate(data.len() / 16 * 16);
    aes_cbc_decrypt(key, &mut data);
    let text = String::from_utf8_lossy(&data);
    let json = text.strip_prefix("MEGA")?.trim_end_matches('\0');
    let value: Value = serde_json::from_str(&json[..=json.rfind('}')?]).ok()?;
    value.get("n")?.as_str().map(str::to_owned)
}

/// Decrypts the file's data in place, given its position in the file.
#[derive(Clone)]
pub struct Cipher {
    key: [u8; 16],
    nonce: [u8; 8],
}

impl Cipher {
    pub fn apply(&self, offset: u64, data: &mut [u8]) {
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&self.nonce);
        let mut ctr = ctr::Ctr128BE::<Aes128>::new(&self.key.into(), &iv.into());
        ctr.seek(offset);
        ctr.apply_keystream(data);
    }
}

/// One file ready to download: a temporary direct address and how to decrypt it.
pub struct Resolved {
    pub url: String,
    pub name: String,
    pub cipher: Cipher,
}

/// A file found in a folder link.
pub struct FolderFile {
    pub handle: String,
    pub name: String,
    /// Sub-folders below the shared folder, outermost first.
    pub dir: Vec<String>,
    pub size: u64,
    pub key: [u8; 32],
}

#[derive(Deserialize)]
struct Node {
    h: String,
    #[serde(default)]
    p: String,
    t: u8,
    #[serde(default)]
    a: String,
    #[serde(default)]
    k: String,
    #[serde(default)]
    s: u64,
}

fn api_error(code: i64) -> anyhow::Error {
    match code {
        -9 => util::fatal("MEGA says this link doesn't exist (it may have been removed)"),
        -11 => util::fatal("MEGA refused access to this link"),
        -16 => util::fatal("MEGA has blocked this link or its owner's account"),
        -17 => util::blocked("MEGA's transfer quota for this NordVPN server is used up"),
        -14 | -2 => util::fatal("The MEGA link's key is wrong"),
        code => anyhow!("MEGA returned error {code}"),
    }
}

/// Calls the MEGA API with one command, retrying while it asks to.
async fn call(client: &Client, folder: Option<&str>, command: Value) -> Result<Value> {
    let mut last_err = None;
    for attempt in 0..ATTEMPTS {
        let mut query = vec![("id", rand::random::<u32>().to_string())];
        if let Some(folder) = folder {
            query.push(("n", folder.to_string()));
        }
        let response = client
            .post(API)
            .query(&query)
            .json(&json!([command]))
            .timeout(Duration::from_secs(60))
            .send()
            .await;
        let value: Value = match response {
            Ok(r) if r.status().is_success() => r.json().await?,
            Ok(r) => {
                last_err = Some(util::http_error(r.status()));
                continue;
            }
            Err(e) => return Err(anyhow!(e).context("Could not reach MEGA")),
        };
        // Errors come back as a bare number or as a number in place of the result.
        let result = value.get(0).cloned().unwrap_or(value);
        match result.as_i64() {
            // EAGAIN, ERATELIMIT, ETEMPUNAVAIL: back off and retry.
            Some(-3 | -4 | -18) => {
                last_err = Some(anyhow!("MEGA is busy"));
                tokio::time::sleep(Duration::from_millis(500 << attempt)).await;
            }
            Some(code) if code < 0 => return Err(api_error(code)),
            _ => return Ok(result),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("MEGA did not answer")))
}

/// Lists a shared folder and decrypts every node's key and name.
async fn folder_nodes(client: &Client, handle: &str, folder_key: &[u8; 16]) -> Result<Vec<(Node, Vec<u8>, String)>> {
    let listing = call(client, Some(handle), json!({"a": "f", "c": 1, "ca": 1, "r": 1})).await?;
    let nodes: Vec<Node> = serde_json::from_value(listing.get("f").cloned().unwrap_or_default())?;
    let mut out = Vec::new();
    for node in nodes {
        // `k` is `<share handle>:<key>`, possibly several separated by '/', each encrypted for a
        // different share. The one encrypted with this folder's key is the one whose name decrypts.
        let decrypted = node.k.split('/').filter_map(|part| part.split_once(':')).filter_map(|(_, encrypted)| {
            let mut key = decode(encrypted).ok().filter(|k| k.len() == 16 || k.len() == 32)?;
            aes_ecb_decrypt(folder_key, &mut key);
            let attr_key: [u8; 16] = if key.len() == 32 {
                unpack_file_key(key.as_slice().try_into().unwrap()).0
            } else {
                key.as_slice().try_into().unwrap()
            };
            Some((decrypt_name(&node.a, &attr_key), key))
        });
        let mut fallback = None;
        let mut found = None;
        for (name, key) in decrypted {
            match name {
                Some(name) => {
                    found = Some((name, key));
                    break;
                }
                None => fallback = fallback.or(Some(key)),
            }
        }
        let Some((name, key)) = found.or_else(|| fallback.map(|key| (node.h.clone(), key))) else {
            continue;
        };
        out.push((node, key, name));
    }
    if out.is_empty() {
        bail!("The MEGA folder is empty, or the link's key is wrong");
    }
    Ok(out)
}

/// The shared folder's name and every file in it, with sub-folder paths.
pub async fn list_folder(client: &Client, handle: &str, key: &[u8; 16]) -> Result<(String, Vec<FolderFile>)> {
    let nodes = folder_nodes(client, handle, key).await?;
    let by_handle: std::collections::HashMap<&str, (&str, &str)> =
        nodes.iter().map(|(n, _, name)| (n.h.as_str(), (n.p.as_str(), name.as_str()))).collect();
    // The root is the folder whose parent isn't part of the listing.
    let root = nodes
        .iter()
        .find(|(n, _, _)| n.t == 1 && !by_handle.contains_key(n.p.as_str()))
        .map(|(n, _, name)| (n.h.clone(), name.clone()));
    let (root_handle, root_name) = root.unwrap_or_else(|| (String::new(), handle.to_string()));
    let mut files = Vec::new();
    for (node, key, name) in nodes.iter().filter(|(n, _, _)| n.t == 0) {
        let Ok(key) = <[u8; 32]>::try_from(key.as_slice()) else { continue };
        let mut dir = Vec::new();
        let mut parent = node.p.as_str();
        while parent != root_handle {
            let Some((grandparent, folder_name)) = by_handle.get(parent) else { break };
            dir.insert(0, folder_name.to_string());
            parent = grandparent;
        }
        files.push(FolderFile { handle: node.h.clone(), name: name.clone(), dir, size: node.s, key });
    }
    files.sort_by(|a, b| (&a.dir, &a.name).cmp(&(&b.dir, &b.name)));
    Ok((root_name, files))
}

/// Gets a temporary download address for a file link or a file inside a folder link.
pub async fn resolve(client: &Client, link: &Link) -> Result<Resolved> {
    match link {
        Link::File { handle, key } => request_file(client, None, json!({"a": "g", "g": 1, "ssl": 2, "p": handle}), key).await,
        Link::Folder { handle, key, file: Some(file) } => {
            let (_, files) = list_folder(client, handle, key).await?;
            let Some(found) = files.into_iter().find(|f| &f.handle == file) else {
                return Err(util::fatal("That file is no longer in the MEGA folder"));
            };
            resolve_in_folder(client, handle, &found.handle, &found.key).await
        }
        Link::Folder { file: None, .. } => bail!("A MEGA folder link has to be split into its files first"),
    }
}

/// Gets a temporary download address for one file of an already listed folder.
pub async fn resolve_in_folder(client: &Client, folder: &str, file: &str, key: &[u8; 32]) -> Result<Resolved> {
    request_file(client, Some(folder), json!({"a": "g", "g": 1, "ssl": 2, "n": file}), key).await
}

async fn request_file(client: &Client, folder: Option<&str>, command: Value, key: &[u8; 32]) -> Result<Resolved> {
    let result = call(client, folder, command).await?;
    let (aes_key, nonce) = unpack_file_key(key);
    let url = result.get("g").and_then(Value::as_str).filter(|g| g.starts_with("https://"));
    let Some(url) = url else {
        bail!("MEGA didn't provide a download address for this file");
    };
    let name = result
        .get("at")
        .and_then(Value::as_str)
        .and_then(|at| decrypt_name(at, &aes_key))
        .unwrap_or_else(|| "download".into());
    Ok(Resolved {
        url: url.to_owned(),
        name,
        cipher: Cipher { key: aes_key, nonce },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_link_formats() {
        let parse = |u: &str| parse(&Url::parse(u).unwrap());
        let folder_key = decode("ivAbogrywnVlZ2uvRq4tww").unwrap();
        let expected = Link::Folder { handle: "DIAmVB5D".into(), key: folder_key.try_into().unwrap(), file: None };
        assert_eq!(parse("https://mega.nz/folder/DIAmVB5D#ivAbogrywnVlZ2uvRq4tww"), Some(expected.clone()));
        assert_eq!(parse("https://mega.nz/#F!DIAmVB5D!ivAbogrywnVlZ2uvRq4tww"), Some(expected));
        let one = parse("https://mega.nz/folder/DIAmVB5D#ivAbogrywnVlZ2uvRq4tww/file/AbCdEfGh");
        assert!(matches!(one, Some(Link::Folder { file: Some(ref f), .. }) if f == "AbCdEfGh"));
        let file = parse(&format!("https://mega.nz/file/AbCdEfGh#{}", B64.encode([5u8; 32])));
        assert!(matches!(file, Some(Link::File { ref handle, .. }) if handle == "AbCdEfGh"));
        assert_eq!(parse("https://mega.nz/folder/DIAmVB5D#short"), None);
        assert_eq!(parse("https://example.com/folder/DIAmVB5D#ivAbogrywnVlZ2uvRq4tww"), None);
    }

    #[test]
    fn ctr_decryption_works_from_any_offset() {
        let cipher = Cipher { key: [7; 16], nonce: [9; 8] };
        let plain: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut whole = plain.clone();
        cipher.apply(0, &mut whole);
        // Decrypt in uneven pieces, as parallel segments arrive.
        let mut pieces = whole.clone();
        for (start, end) in [(0, 5), (5, 333), (333, 999), (999, 1000)] {
            cipher.apply(start as u64, &mut pieces[start..end]);
        }
        assert_eq!(pieces, plain);
    }

    /// Lists a real folder through a NordVPN server and checks ranged, decryptable downloads:
    /// `MEGA_TEST_URL=<folder link> cargo test live_mega -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn live_mega_folder() {
        use crate::{browser, nord, settings};
        let url = Url::parse(&std::env::var("MEGA_TEST_URL").expect("MEGA_TEST_URL")).unwrap();
        let Some(Link::Folder { handle, key, .. }) = parse(&url) else { panic!("not a folder link") };
        let api = Client::builder().emulation(browser::emulation()).user_agent(nord::APP_USER_AGENT).build().unwrap();
        let creds = settings::load_credentials().expect("signed in to NordVPN");
        let selected = nord::select(&api, &creds, None, &Default::default()).await.expect("NordVPN server");
        println!("server {}", selected.info.hostname);
        let client = selected.client;
        let t = std::time::Instant::now();
        let (root, files) = list_folder(&client, &handle, &key).await.unwrap();
        let total: u64 = files.iter().map(|f| f.size).sum();
        println!("folder {root:?}: {} files, {} total, listed in {:?}", files.len(), util::format_size(total), t.elapsed());
        for f in files.iter().take(1) {
            let t = std::time::Instant::now();
            let r = resolve_in_folder(&client, &handle, &f.handle, &f.key).await.unwrap();
            let got_link = t.elapsed();
            let body = client.get(&r.url).send().await.unwrap().bytes().await.unwrap();
            let secs = t.elapsed().as_secs_f64() - got_link.as_secs_f64();
            println!("TIMING link {got_link:?}, {} bytes in {secs:.1}s = {:.0} KB/s ({})", body.len(), body.len() as f64 / secs / 1024.0, r.url.split('/').nth(2).unwrap_or(""));
        }
        // Same file over 4 parallel ranges: is MEGA's limit per connection or per IP?
        let big = files.iter().max_by_key(|f| f.size).unwrap();
        let r = resolve_in_folder(&client, &handle, &big.handle, &big.key).await.unwrap();
        let chunk = 1u64 << 20;
        let t = std::time::Instant::now();
        let parts = futures_util::future::join_all((0..4u64).map(|i| {
            let (client, url) = (client.clone(), r.url.clone());
            async move {
                let range = format!("bytes={}-{}", i * chunk, (i + 1) * chunk - 1);
                match client.get(&url).header("Range", range).send().await {
                    Ok(r) => match r.bytes().await {
                        Ok(b) => b.len(),
                        Err(e) => { println!("TIMING body error: {e:#}"); 0 }
                    },
                    Err(e) => { println!("TIMING send error: {e:#}"); 0 }
                }
            }
        }))
        .await;
        let total: usize = parts.iter().sum();
        let secs = t.elapsed().as_secs_f64();
        println!("TIMING 4 parallel ranges: {total} bytes in {secs:.1}s = {:.0} KB/s total", total as f64 / secs / 1024.0);
        for f in files.iter().take(5) {
            println!("  {}/{}", f.dir.join("/"), f.name);
        }
        let undecrypted: Vec<_> = files.iter().filter(|f| f.name == f.handle).map(|f| f.dir.join("/")).collect();
        println!("names that didn't decrypt: {} {:?}", undecrypted.len(), undecrypted.iter().take(5).collect::<Vec<_>>());
        assert!(undecrypted.is_empty(), "every file name should decrypt");
        let first = &files[0];
        let link = Link::Folder { handle: handle.clone(), key, file: Some(first.handle.clone()) };
        let resolved = resolve(&client, &link).await.unwrap();
        println!("{}", resolved.name);
        let response = client.get(&resolved.url).header("Range", "bytes=16-31").send().await.unwrap();
        println!("range status {} content-range {:?}", response.status(), response.headers().get("content-range"));
        assert_eq!(response.status(), 206);
        let mut bytes = response.bytes().await.unwrap().to_vec();
        resolved.cipher.apply(16, &mut bytes);
        println!("decrypted bytes 16..32: {:02x?}", bytes);
    }
}
