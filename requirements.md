# Nord Download Manager — Requirements

A Windows desktop download manager that fetches each file over parallel connections, with every
download routed through its own NordVPN server.

## 1. Platform & delivery

| # | Requirement | Status |
|---|---|---|
| 1.1 | Desktop app for Windows, built with Tauri (Rust backend, TypeScript frontend). | Done |
| 1.2 | Ships as a **single portable exe**. No installer. Built with `cargo tauri build --no-bundle`. | Done |

## 2. Downloading

| # | Requirement | Status |
|---|---|---|
| 2.1 | Download a link over **multiple parallel connections** (byte ranges) for speed. | Done |
| 2.2 | Keep every connection busy until the end: connections that finish early take over half of a slower one's remaining work. | Done |
| 2.3 | Fall back to a single connection when the server doesn't support ranged requests. | Done |
| 2.4 | Pause, resume and remove downloads; resume survives an app restart. | Done |
| 2.5 | Retry dropped connections automatically without corrupting the file. | Done |

## 3. Parallel connection count

| # | Requirement | Status |
|---|---|---|
| 3.1 | Recommend a default number of connections from the CPU core count and other factors (free RAM, file size, other running downloads). | Done |
| 3.2 | Let the user change the number per download (1–32). | Done |

## 4. NordVPN routing

| # | Requirement | Status |
|---|---|---|
| 4.1 | Every download goes through a NordVPN server. **Never download directly.** | Done |
| 4.2 | **Each download uses its own, separate NordVPN connection**, used only by this app. The rest of the machine's traffic is not affected. | Done (NordVPN HTTPS proxy per download) |
| 4.3 | Pick a **random** server from regions known to be fast: Western Europe, USA, Canada, Australia, Singapore, Japan, Hong Kong. | Done |
| 4.4 | Prefer lightly loaded servers using NordVPN's published load. **No speed tests.** | Done |
| 4.5 | Don't give two running downloads the same server. | Done |
| 4.6 | Check that traffic really leaves from a NordVPN IP before using a server. | Done |
| 4.7 | If a server fails or a site blocks it (e.g. Cloudflare bot check), switch to another random server, up to 5 attempts. | Done |
| 4.8 | Optional setting to force a specific country. | Done |

## 5. Sign-in

| # | Requirement | Status |
|---|---|---|
| 5.1 | Sign in to NordVPN **once** and have it remembered indefinitely (stored in Windows Credential Manager). | Done |
| 5.2 | Sign in through the app. | Done, via a Nord Account access token (or service credentials). Email/password sign-in isn't possible: NordVPN blocks it for third-party apps. |
| 5.3 | Check credentials against a real NordVPN server before saving, with clear errors (wrong credentials, email entered, bad token). | Done |

## 6. Interface

| # | Requirement | Status |
|---|---|---|
| 6.1 | Plain, uncluttered design. No explanatory clutter or "AI slop". | Done |
| 6.2 | Large, easy-to-read elements (built for a 4K screen). | Done |
| 6.3 | Large, colourful action buttons: Pause, Resume, Open, Show in folder, Remove. | Done |
| 6.4 | **Copy link** button on each download. | Done |
| 6.5 | Show the NordVPN connection for each download: **exit IP, city and country**. | Done |
| 6.6 | Show **"Connecting to NordVPN…"** while a server is being picked. | Done |
| 6.7 | Show progress, speed, time left and active connections per download. | Done |
| 6.8 | Improved app icon. | Done |

## 7. Reliability

| # | Requirement | Status |
|---|---|---|
| 7.1 | Stable: the window never freezes, even if a download misbehaves. | Done (all commands run off the UI thread; deadlock fixed) |
| 7.2 | Clear error messages when a download can't complete. | Done |
| 7.3 | Automated tests for parallel downloading, resume, and NordVPN sign-in and routing. | Done (12 tests, including live NordVPN and gofile runs) |

## 8. File hosts

| # | Requirement | Status |
|---|---|---|
| 8.1 | gofile.io links download without manual steps. | Done. Both gofile.io/d/ share links and direct /download/web/ links are resolved through gofile's API with a guest account created through the download's NordVPN server (tested live with a real direct link). The user's own gofile token (Settings) is optional. |
| 8.2 | MEGA file and folder links download without manual steps. | Done. Files are decrypted as they download; a folder link is one download that saves the whole folder (with sub-folders), several files at a time through one NordVPN server. Removing a download closes its NordVPN connections (tested live). |
