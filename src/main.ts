import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ask, open as openDialog } from "@tauri-apps/plugin-dialog";
import { formatBytes, formatEta, formatSpeed } from "./format";
import type { Country, DownloadView, ProgressUpdate, Recommendation, Settings, SettingsView } from "./types";

const byId = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = ""): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

function errorText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}

async function busy(button: HTMLButtonElement, label: string, work: () => Promise<void>) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = label;
  try {
    await work();
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

let view: SettingsView;
const downloads = new Map<string, DownloadView>();
const order: string[] = [];
const items = new Map<string, Item>();

// ---------- sign in ----------

function showScreen() {
  const signedIn = view.account != null;
  byId("signin").classList.toggle("hidden", signedIn);
  byId("app").classList.toggle("hidden", !signedIn);
  (signedIn ? byId("url") : byId("token")).focus();
}

async function refreshSettings() {
  view = await invoke<SettingsView>("get_settings");
}

function toggleSignInMode(useCreds: boolean) {
  byId("token-form").classList.toggle("hidden", useCreds);
  byId("creds-form").classList.toggle("hidden", !useCreds);
  byId("signin-error").textContent = "";
  (useCreds ? byId("svc-user") : byId("token")).focus();
}

async function signIn(form: HTMLFormElement, command: string, args: Record<string, string>) {
  const button = form.querySelector<HTMLButtonElement>("button[type=submit]")!;
  const error = byId("signin-error");
  error.textContent = "";
  await busy(button, "Checking…", async () => {
    try {
      await invoke(command, args);
      await refreshSettings();
      showScreen();
    } catch (e) {
      error.textContent = errorText(e);
    }
  });
}

byId("token-form").addEventListener("submit", (e) => {
  e.preventDefault();
  signIn(e.target as HTMLFormElement, "sign_in_with_token", { token: byId<HTMLInputElement>("token").value });
});

byId("creds-form").addEventListener("submit", (e) => {
  e.preventDefault();
  signIn(e.target as HTMLFormElement, "sign_in", {
    username: byId<HTMLInputElement>("svc-user").value,
    password: byId<HTMLInputElement>("svc-pass").value,
  });
});

byId("use-creds").addEventListener("click", (e) => {
  e.preventDefault();
  toggleSignInMode(true);
});
byId("use-token").addEventListener("click", (e) => {
  e.preventDefault();
  toggleSignInMode(false);
});
for (const link of document.querySelectorAll(".open-account")) {
  link.addEventListener("click", (e) => {
    e.preventDefault();
    invoke("open_nord_account");
  });
}

// ---------- adding downloads ----------

const urlInput = byId<HTMLInputElement>("url");
const connInput = byId<HTMLInputElement>("conn");
const addError = byId("add-error");

async function loadRecommendation() {
  const rec = await invoke<Recommendation>("system_recommendation");
  connInput.value = String(rec.connections);
  connInput.max = String(rec.max);
  byId("conn-label").title =
    `Recommended: ${rec.connections}\n${rec.reasons.join("\n")}\nSmall files automatically use fewer.`;
}

byId("add-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return urlInput.focus();
  addError.textContent = "";
  const connections = Math.min(32, Math.max(1, Math.round(Number(connInput.value)) || 1));
  try {
    upsert(await invoke<DownloadView>("add_download", { request: { url, connections } }));
    urlInput.value = "";
  } catch (err) {
    addError.textContent = errorText(err);
  }
});

urlInput.addEventListener("input", () => (addError.textContent = ""));

// ---------- download list ----------

interface Item {
  root: HTMLElement;
  name: HTMLElement;
  pct: HTMLElement;
  bar: HTMLCanvasElement;
  info: HTMLElement;
  server: HTMLElement;
  actions: HTMLElement;
  actionsFor?: string;
}

function upsert(d: DownloadView) {
  const previous = downloads.get(d.id);
  downloads.set(d.id, { ...previous, ...d });
  if (!previous) order.unshift(d.id);
  renderList();
}

function renderList() {
  const list = byId("list");
  const nodes = order.flatMap((id) => {
    const d = downloads.get(id);
    if (!d) return [];
    let item = items.get(id);
    if (!item) items.set(id, (item = createItem()));
    updateItem(item, d);
    return [item.root];
  });
  const current = Array.from(list.children);
  if (current.length !== nodes.length || current.some((node, i) => node !== nodes[i])) {
    list.replaceChildren(...nodes);
  }
  byId("empty").classList.toggle("hidden", nodes.length > 0);
}

function createItem(): Item {
  const root = el("div", "item");
  const top = el("div", "item-top");
  const name = el("span", "name");
  const pct = el("span", "pct");
  top.append(name, pct);
  const bar = el("canvas", "bar");
  const info = el("div", "info");
  const server = el("div", "server");
  const actions = el("div", "actions");
  root.append(top, bar, info, server, actions);
  return { root, name, pct, bar, info, server, actions };
}

function renderServer(item: Item, d: DownloadView) {
  item.server.replaceChildren();
  const s = d.server;
  if (!s) return;
  const place = [s.city, s.country].filter(Boolean).join(", ");
  const verb = d.status === "completed" ? "Downloaded via" : "Connected via";
  item.server.append(`${verb} NordVPN `);
  item.server.append(el("b", "", s.exitIp ?? s.hostname));
  item.server.append(` · ${place} · ${s.hostname.split(".")[0]}`);
}

function infoText(d: DownloadView): string {
  const size = d.totalSize != null ? formatBytes(d.totalSize) : "";
  switch (d.status) {
    case "connecting":
      return d.statusText ?? "Connecting to NordVPN…";
    case "downloading": {
      const parts = [
        `${formatBytes(d.downloaded)} of ${size || "?"}`,
        formatSpeed(d.speed),
        d.eta != null ? `${formatEta(d.eta)} left` : "",
        `${d.activeConnections} connections`,
      ];
      return parts.filter(Boolean).join(" · ");
    }
    case "paused":
      return ["Paused", size ? `${formatBytes(d.downloaded)} of ${size}` : ""].filter(Boolean).join(" · ");
    case "completed":
      return `Done · ${size || formatBytes(d.downloaded)}`;
    case "error":
      return d.error ?? "Failed";
  }
}

function updateItem(item: Item, d: DownloadView) {
  item.root.dataset.status = d.status;
  item.name.textContent = d.fileName;
  item.name.title = d.url;
  const fraction = d.status === "completed" ? 1 : d.totalSize ? d.downloaded / d.totalSize : 0;
  item.pct.textContent = d.status === "completed" || !d.totalSize ? "" : `${Math.floor(fraction * 100)}%`;
  item.info.textContent = infoText(d);
  renderServer(item, d);
  if (item.actionsFor !== d.status) {
    item.actionsFor = d.status;
    renderActions(item, d);
  }
  drawBar(item.bar, d);
}

const svg = (path: string) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;
const ICONS: Record<string, string> = {
  pause: svg('<path d="M9 5v14M15 5v14"/>'),
  resume: svg('<path d="M7 4.5v15l12-7.5z" fill="currentColor"/>'),
  open: svg('<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>'),
  folder: svg('<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'),
  copy: svg('<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>'),
  remove: svg('<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-12M9 7V4h6v3"/>'),
};

function renderActions(item: Item, d: DownloadView) {
  const id = d.id;
  const action = (label: string, run: () => Promise<unknown>) => {
    const kind = label.split(" ")[0].toLowerCase().replace("show", "folder");
    const button = el("button", kind);
    button.innerHTML = ICONS[kind] ?? "";
    button.append(label);
    button.type = "button";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await run();
      } catch (e) {
        const current = downloads.get(id);
        if (current) upsert({ ...current, status: "error", error: errorText(e) });
      } finally {
        button.disabled = false;
      }
    });
    return button;
  };
  const buttons: HTMLButtonElement[] = [];
  if (d.status === "downloading" || d.status === "connecting") {
    buttons.push(action("Pause", () => invoke("pause_download", { id })));
  } else if (d.status === "paused" || d.status === "error") {
    buttons.push(action("Resume", () => invoke("resume_download", { id })));
  } else if (d.status === "completed") {
    buttons.push(action("Open", () => invoke("open_download", { id })));
  }
  buttons.push(action("Show in folder", () => invoke("reveal_download", { id })));
  const copy = action("Copy link", async () => {
    await navigator.clipboard.writeText(downloads.get(id)?.url ?? d.url);
    copy.lastChild!.textContent = "Copied";
    setTimeout(() => (copy.lastChild!.textContent = "Copy link"), 1500);
  });
  buttons.push(copy);
  buttons.push(
    action("Remove", async () => {
      const current = downloads.get(id);
      if (current && current.status !== "completed") {
        const ok = await ask(`Cancel "${current.fileName}" and delete the partial file?`, {
          title: "Remove download",
          kind: "warning",
        });
        if (!ok) return;
      }
      await invoke("remove_download", { id, deleteFile: false });
    }),
  );
  item.actions.replaceChildren(...buttons);
}

function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function drawBar(canvas: HTMLCanvasElement, d: DownloadView) {
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (!width) return;
  if (canvas.width !== Math.round(width * dpr) || canvas.height !== Math.round(height * dpr)) {
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
  }
  const ctx = canvas.getContext("2d")!;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.fillStyle = cssVar("--track");
  ctx.fillRect(0, 0, width, height);
  if (d.status === "completed") {
    ctx.fillStyle = cssVar("--done");
    ctx.fillRect(0, 0, width, height);
    return;
  }
  const total = d.totalSize;
  if (!total) return;
  ctx.fillStyle = cssVar(d.status === "paused" ? "--warn" : d.status === "error" ? "--error" : "--accent");
  // Each connection's segment fills independently, so parallel progress is visible.
  for (const s of d.segments) {
    ctx.fillRect((s.start / total) * width, 0, ((Math.min(s.pos, s.end) - s.start) / total) * width, height);
  }
}

new ResizeObserver(() => {
  for (const [id, item] of items) {
    const d = downloads.get(id);
    if (d) drawBar(item.bar, d);
  }
}).observe(byId("list"));

// ---------- settings ----------

const dialog = byId<HTMLDialogElement>("settings");
let countriesLoaded = false;

async function saveSettings(change: Partial<Settings>) {
  const settings = { ...view.settings, ...change };
  await invoke("save_settings", { settings });
  view.settings = settings;
}

function showGofileState() {
  byId<HTMLInputElement>("gofile").value = "";
  byId<HTMLInputElement>("gofile").placeholder = view.hasGofileToken ? "•••••••• (saved)" : "Optional";
  byId("gofile-state").textContent = "gofile.io links download automatically. A token is only needed if one doesn't: gofile.io → My profile → Account token.";
}

byId("save-gofile").addEventListener("click", async () => {
  const token = byId<HTMLInputElement>("gofile").value;
  try {
    await invoke("save_gofile_token", { token });
    view.hasGofileToken = token.trim() !== "";
    showGofileState();
    byId("gofile-state").textContent = view.hasGofileToken ? "Saved." : "Removed.";
  } catch (e) {
    byId("gofile-state").textContent = errorText(e);
  }
});

byId("open-settings").addEventListener("click", async () => {
  byId("account").textContent = view.account ?? "";
  showGofileState();
  byId("dir").textContent = view.settings.downloadDir;
  byId("dir").title = view.settings.downloadDir;
  const select = byId<HTMLSelectElement>("country");
  dialog.showModal();
  if (!countriesLoaded) {
    try {
      for (const c of await invoke<Country[]>("list_countries")) {
        const option = el("option", "", c.name);
        option.value = String(c.id);
        select.append(option);
      }
      countriesLoaded = true;
    } catch {
      // Optional: "Nearest" still works without the list.
    }
  }
  select.value = view.settings.countryId != null ? String(view.settings.countryId) : "";
});

byId("country").addEventListener("change", (e) => {
  const value = (e.target as HTMLSelectElement).value;
  saveSettings({ countryId: value ? Number(value) : null });
});

byId("change-dir").addEventListener("click", async () => {
  const dir = await openDialog({ directory: true, defaultPath: view.settings.downloadDir || undefined });
  if (typeof dir === "string") {
    await saveSettings({ downloadDir: dir });
    byId("dir").textContent = dir;
    byId("dir").title = dir;
  }
});

byId("sign-out").addEventListener("click", async () => {
  await invoke("sign_out");
  await refreshSettings();
  dialog.close();
  showScreen();
});

byId("close-settings").addEventListener("click", () => dialog.close());

// ---------- startup ----------

async function init() {
  await refreshSettings();
  for (const d of await invoke<DownloadView[]>("list_downloads")) {
    downloads.set(d.id, d);
    order.push(d.id);
  }
  renderList();
  await loadRecommendation();

  await listen<DownloadView>("download-updated", (e) => upsert(e.payload));
  await listen<string>("download-removed", (e) => {
    downloads.delete(e.payload);
    items.delete(e.payload);
    const index = order.indexOf(e.payload);
    if (index >= 0) order.splice(index, 1);
    renderList();
  });
  await listen<ProgressUpdate[]>("downloads-progress", (e) => {
    for (const update of e.payload) {
      const d = downloads.get(update.id);
      if (!d) continue;
      Object.assign(d, update);
      const item = items.get(update.id);
      if (item) updateItem(item, d);
    }
  });

  showScreen();
}

init();
