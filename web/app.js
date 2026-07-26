import init, {
  unlock, lock, empty_vault_json, generate_password, lock_file, unlock_file,
} from "./pkg/vault_wasm.js";

// ---- App state -------------------------------------------------------------
const state = {
  vault: null,        // { schema, entries: [] }
  password: null,     // master password, kept only in memory while unlocked
  filename: "vault.locked",
  dirty: false,
  loadedBytes: null,  // Uint8Array of a picked file, awaiting unlock
  editingId: null,    // id being edited, or null when adding
  snapshot: null,     // encrypted in-memory copy of unsaved work, kept across a lock
  snapshotName: null,
  lockerBytes: null,  // bytes of a file selected in the "file locker" tab
  lockerName: null,
};

const AUTOLOCK_ACTIVITY = ["mousemove", "keydown", "click", "input", "scroll"];
let lockTimer = null;

const $ = (id) => document.getElementById(id);

// ---- Boot ------------------------------------------------------------------
await init();
wireLockScreen();
wireVaultScreen();
wireDialog();
wireFileLocker();
// Any interaction postpones auto-lock; the timer only arms while unlocked.
AUTOLOCK_ACTIVITY.forEach((ev) => document.addEventListener(ev, resetAutoLock, { passive: true }));

// ===========================================================================
// Lock screen
// ===========================================================================
function wireLockScreen() {
  $("tab-new").onclick = () => switchTab("new");
  // Clicking a file tab is a user gesture, so we open the OS picker right away.
  // Cancelling the picker just leaves the tab open — click it again to retry.
  $("tab-open").onclick = () => { switchTab("open"); $("file-input").click(); };
  $("tab-file").onclick = () => { switchTab("file"); $("file-input2").click(); };

  $("file-input").onchange = () => $("file-input").files[0] && loadFile($("file-input").files[0]);

  $("open-password").addEventListener("keydown", (e) => { if (e.key === "Enter") $("open-btn").click(); });
  $("open-btn").onclick = doUnlock;
  $("new-btn").onclick = doCreate;
  $("new-password").addEventListener("input", updateNewStrength);
}

function switchTab(which) {
  for (const t of ["open", "new", "file"]) {
    $("tab-" + t).classList.toggle("active", which === t);
    $("pane-" + t).classList.toggle("hidden", which !== t);
  }
  lockError("");
}

async function loadFile(file) {
  state.loadedBytes = new Uint8Array(await file.arrayBuffer());
  state.filename = file.name;
  $("file-label").textContent = "📄 " + file.name;
  $("file-label").classList.remove("hidden");
  $("open-btn").disabled = false;
  lockError("");
}

function doUnlock() {
  const pw = $("open-password").value;
  // Unlock a picked file, or — if none — restore an unsaved snapshot from a
  // previous lock (both are encrypted with the same master password).
  const bytes = state.loadedBytes || state.snapshot;
  if (!bytes) return lockError("Choose a vault file first.");
  if (!pw) return lockError("Enter your master password.");
  try {
    const json = unlock(bytes, pw); // throws on wrong password
    const restored = !state.loadedBytes && !!state.snapshot;
    state.vault = JSON.parse(json);
    state.password = pw;
    if (restored) state.filename = state.snapshotName || state.filename;
    state.dirty = restored; // a restored snapshot is still unsaved
    state.snapshot = null;
    state.snapshotName = null;
    enterVault();
    if (restored) toast("Restored unsaved state");
  } catch (e) {
    lockError(String(e));
  }
}

function doCreate() {
  const pw = $("new-password").value, pw2 = $("new-password2").value;
  if (pw.length < 12) return lockError("Master password must be at least 12 characters (a passphrase is best).");
  if (pw !== pw2) return lockError("Passwords don't match.");
  state.vault = JSON.parse(empty_vault_json());
  state.password = pw;
  state.filename = vaultFilename($("new-name").value);
  state.dirty = true; // nothing saved yet
  enterVault();
}

// Turn a user-typed vault name into a safe ".locked" filename ("work" -> "work.locked").
function vaultFilename(name) {
  const base = name.trim()
    .replace(/\.(locked|psv)$/i, "") // don't double the extension
    .replace(/[^\w .-]+/g, "")        // drop characters unsafe in filenames
    .trim()
    .replace(/\s+/g, "-");            // spaces -> dashes
  return (base || "vault") + ".locked";
}

function lockError(msg) { $("lock-error").textContent = msg; }

// ===========================================================================
// File locker — encrypt / decrypt any single file (no vault involved)
// ===========================================================================
function wireFileLocker() {
  const input = $("file-input2"), drop = $("file-drop2");
  input.onchange = () => input.files[0] && loadLockerFile(input.files[0]);
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("drag"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("drag"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault(); drop.classList.remove("drag");
    if (e.dataTransfer.files[0]) loadLockerFile(e.dataTransfer.files[0]);
  });
  $("file-password").addEventListener("input", updateLockerButtons);
  $("encrypt-file-btn").onclick = encryptFile;
  $("decrypt-file-btn").onclick = decryptFile;
}

async function loadLockerFile(file) {
  state.lockerBytes = new Uint8Array(await file.arrayBuffer());
  state.lockerName = file.name;
  $("file-label2").textContent = `${file.name} (${file.size} bytes)`;
  $("file-drop2").classList.add("loaded");
  updateLockerButtons();
  lockError("");
  $("file-password").focus(); // ready to type the password immediately
}

// The file's extension decides the operation: an already-encrypted file
// (".filelocked", or legacy ".locked"/".psv") -> decrypt, anything else ->
// encrypt. Only the matching button shows, once a file and password are set.
function updateLockerButtons() {
  const enc = $("encrypt-file-btn"), dec = $("decrypt-file-btn");
  if (!state.lockerBytes) {
    enc.classList.add("hidden");
    dec.classList.add("hidden");
    return;
  }
  const isLocked = /\.(filelocked|locked|psv)$/i.test(state.lockerName);
  const hasPw = $("file-password").value.length > 0;
  enc.classList.toggle("hidden", isLocked);
  dec.classList.toggle("hidden", !isLocked);
  enc.disabled = !hasPw;
  dec.disabled = !hasPw;
}

function encryptFile() {
  const pw = $("file-password").value;
  if (!state.lockerBytes || !pw) return;
  try {
    const out = lock_file(state.lockerBytes, pw);
    download(out, state.lockerName + ".filelocked");
    toast("File encrypted");
  } catch (e) { lockError(String(e)); }
}

function decryptFile() {
  const pw = $("file-password").value;
  if (!state.lockerBytes || !pw) return;
  try {
    const out = unlock_file(state.lockerBytes, pw); // throws on wrong password
    // Strip our encrypted-file suffix to restore the original name, e.g.
    // "AndriiSukhodieiev.pfx.filelocked" -> ".pfx". (".locked"/".psv" = legacy.)
    const name = state.lockerName.replace(/\.(filelocked|locked|psv)$/i, "") || "decrypted";
    download(out, name);
    toast("File decrypted");
  } catch (e) { lockError(String(e)); }
}

// Trigger a browser download of the given bytes.
function download(bytes, filename) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ===========================================================================
// Vault screen
// ===========================================================================
function wireVaultScreen() {
  $("add-btn").onclick = () => openDialog(null);
  $("save-btn").onclick = saveFile;
  $("lock-btn").onclick = () => lockVault("manual");
  $("search").oninput = renderEntries;
  $("autolock").onchange = resetAutoLock;
}

function enterVault() {
  $("lock-screen").classList.add("hidden");
  $("vault-screen").classList.remove("hidden");
  $("open-password").value = "";
  $("new-name").value = "";
  $("new-password").value = "";
  $("new-password2").value = "";
  $("new-strength-bar").style.width = "0";
  $("new-strength-label").textContent = "";
  $("vault-name").textContent = "🔐 " + state.filename;
  renderEntries();
  updateDirty();
  updateRestoreNote();
  resetAutoLock();
}

function lockVault(reason) {
  // Preserve unsaved edits across a lock as an *encrypted* in-memory snapshot,
  // so auto-lock never silently loses work. Plaintext + password are dropped.
  if (state.vault && state.password && state.dirty) {
    try {
      state.snapshot = lock(JSON.stringify(state.vault), state.password);
      state.snapshotName = state.filename;
    } catch { state.snapshot = null; }
  }
  clearTimeout(lockTimer);
  state.vault = null;
  state.password = null;
  state.loadedBytes = null;
  state.dirty = false;
  state.editingId = null;
  if ($("entry-dialog").open) $("entry-dialog").close();
  $("file-label").textContent = "";
  $("file-label").classList.add("hidden");
  $("open-btn").disabled = !state.snapshot; // snapshot can be unlocked with just a password
  $("open-password").value = "";
  $("vault-screen").classList.add("hidden");
  $("lock-screen").classList.remove("hidden");
  switchTab("open");
  updateRestoreNote();
  if (reason === "auto") toast("Locked due to inactivity");
}

// Arm/refresh the inactivity timer. No-op while locked or when set to "off".
function resetAutoLock() {
  clearTimeout(lockTimer);
  if (!state.vault) return;
  const ms = +$("autolock").value;
  if (ms > 0) lockTimer = setTimeout(() => lockVault("auto"), ms);
}

function updateRestoreNote() {
  $("restore-note").classList.toggle("hidden", !state.snapshot);
}

function renderEntries() {
  const q = $("search").value.trim().toLowerCase();
  const list = $("entry-list");
  list.innerHTML = "";

  const items = state.vault.entries
    .filter((e) => !q || (e.title + e.username + e.url).toLowerCase().includes(q))
    .sort((a, b) => a.title.localeCompare(b.title));

  $("empty-note").classList.toggle("hidden", state.vault.entries.length !== 0);

  for (const e of items) {
    const li = document.createElement("li");
    li.className = "entry";
    li.innerHTML = `
      <div class="info">
        <div class="title"></div>
        <div class="sub"></div>
        <code class="pw hidden"></code>
      </div>
      <div class="actions">
        <button class="small ghost" data-act="reveal" title="Show password">👁</button>
        <button class="small" data-act="copy">Copy</button>
        <button class="small" data-act="edit">✏️</button>
        <button class="small ghost" data-act="del">🗑</button>
      </div>`;
    li.querySelector(".title").textContent = e.title || "(untitled)";
    li.querySelector(".sub").textContent = [e.username, e.url].filter(Boolean).join(" · ");
    const pwEl = li.querySelector(".pw");
    const revealBtn = li.querySelector('[data-act="reveal"]');
    revealBtn.onclick = () => {
      const nowHidden = pwEl.classList.toggle("hidden");
      pwEl.textContent = nowHidden ? "" : e.password;
      revealBtn.textContent = nowHidden ? "👁" : "🙈";
    };
    li.querySelector('[data-act="copy"]').onclick = () => copyPassword(e);
    li.querySelector('[data-act="edit"]').onclick = () => openDialog(e.id);
    li.querySelector('[data-act="del"]').onclick = () => deleteEntry(e.id);
    list.appendChild(li);
  }
}

async function copyPassword(entry) {
  try {
    await navigator.clipboard.writeText(entry.password);
    toast("Password copied");
  } catch {
    toast("Copy failed");
  }
}

function deleteEntry(id) {
  const e = state.vault.entries.find((x) => x.id === id);
  if (!confirm(`Delete “${e?.title || "entry"}”?`)) return;
  state.vault.entries = state.vault.entries.filter((x) => x.id !== id);
  markDirty();
  renderEntries();
}

async function saveFile() {
  try {
    const bytes = lock(JSON.stringify(state.vault), state.password);
    download(bytes, state.filename || "vault.locked");
    state.dirty = false;
    updateDirty();
    toast("Saved");
  } catch (e) {
    toast("Save failed: " + e);
  }
}

function markDirty() { state.dirty = true; updateDirty(); }
function updateDirty() { $("dirty-note").classList.toggle("hidden", !state.dirty); }

// ===========================================================================
// Entry dialog
// ===========================================================================
function wireDialog() {
  $("gen-btn").onclick = () => {
    const len = Math.min(128, Math.max(4, +$("gen-len").value || 20));
    $("f-password").value = generate_password(len, $("gen-sym").checked);
    updateStrength();
  };
  $("reveal-btn").onclick = () => toggleReveal($("f-password"), $("reveal-btn"));
  $("f-password").addEventListener("input", updateStrength);
  $("entry-form").addEventListener("submit", (ev) => {
    // dialog forms submit with the clicked button's value
    if (ev.submitter && ev.submitter.value === "save") applyDialog();
  });
}

function openDialog(id) {
  state.editingId = id;
  const e = id ? state.vault.entries.find((x) => x.id === id) : null;
  $("dialog-title").textContent = id ? "Edit entry" : "New entry";
  $("f-title").value = e?.title || "";
  $("f-username").value = e?.username || "";
  $("f-password").value = e?.password || "";
  $("f-url").value = e?.url || "";
  $("f-notes").value = e?.notes || "";
  $("f-password").type = "password"; // always start hidden
  $("reveal-btn").textContent = "👁";
  updateStrength();
  $("entry-dialog").showModal();
}

function toggleReveal(input, btn) {
  const reveal = input.type === "password";
  input.type = reveal ? "text" : "password";
  btn.textContent = reveal ? "🙈" : "👁";
}

// Rough entropy estimate: length × log2(character-pool size). Returns bits, a
// label/color, and a 0–100 percentage (~100 bits fills the bar).
function scorePassword(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  const bits = pw ? pw.length * Math.log2(pool || 1) : 0;

  let label = "", color = "transparent";
  if (bits > 0 && bits < 40) { label = "Weak"; color = "#ff5c5c"; }
  else if (bits < 60) { label = "Fair"; color = "#ffb020"; }
  else if (bits < 80) { label = "Good"; color = "#43c47a"; }
  else if (bits >= 80) { label = "Strong"; color = "#2fe08a"; }
  return { bits, label, color, pct: Math.min(100, Math.round(bits)) };
}

// Paint a strength bar (and optional text label) for the given password string.
function paintStrength(pw, barId, labelId) {
  const { label, color, pct } = scorePassword(pw);
  const bar = $(barId);
  bar.style.width = pct + "%";
  bar.style.background = color;
  if (labelId) {
    const lbl = $(labelId);
    lbl.textContent = label;
    lbl.style.color = color;
  }
}

function updateStrength() { paintStrength($("f-password").value, "strength-bar", "strength-label"); }
function updateNewStrength() { paintStrength($("new-password").value, "new-strength-bar", "new-strength-label"); }

function applyDialog() {
  const now = Math.floor(Date.now() / 1000);
  const data = {
    title: $("f-title").value.trim(),
    username: $("f-username").value,
    password: $("f-password").value,
    url: $("f-url").value.trim(),
    notes: $("f-notes").value,
  };
  if (state.editingId) {
    const e = state.vault.entries.find((x) => x.id === state.editingId);
    Object.assign(e, data, { updated: now });
  } else {
    state.vault.entries.push({ id: newId(), ...data, created: now, updated: now });
  }
  markDirty();
  renderEntries();
}

function newId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// ---- Toast -----------------------------------------------------------------
let toastTimer = null;
function toast(msg) {
  let t = document.querySelector(".toast");
  if (!t) { t = document.createElement("div"); t.className = "toast"; document.body.appendChild(t); }
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 1600);
}
