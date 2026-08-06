import init, {
  unlock, lock, empty_vault_json, generate_password, lock_file, unlock_file,
  decode_qr, parse_otpauth, totp_code, totp_qr_svg,
} from "./pkg/vault_wasm.js";

// ---- App state -------------------------------------------------------------
const state = {
  vault: null,        // { schema, entries: [] }
  password: null,     // master password, kept only in memory while unlocked
  filename: "vault.locked",
  dirty: false,
  loadedBytes: null,  // Uint8Array of a picked file, awaiting unlock
  fileHandle: null,   // File System Access handle of the opened vault (for save-in-place)
  editingId: null,    // id being edited, or null when adding
  editingTotp: null,  // the entry dialog's pending 2FA secret (a Totp object or null)
  liveCodes: [],      // list-row TOTP displays refreshed once a second
  snapshot: null,     // encrypted in-memory copy of unsaved work, kept across a lock
  snapshotName: null,
  lockerBytes: null,  // bytes of a file selected in the "file locker" tab
  lockerName: null,
};

const AUTOLOCK_ACTIVITY = ["mousemove", "keydown", "click", "input", "scroll"];
let lockTimer = null;

const $ = (id) => document.getElementById(id);
// Reference an icon from the inline SVG sprite.
const icon = (id) => `<svg class="icon" aria-hidden="true"><use href="#${id}"/></svg>`;
// Minimum master-password length required to encrypt (a new password).
const MIN_MASTER_PW = 12;
// Build a <code> element with safe text content.
const codeEl = (text) => { const c = document.createElement("code"); c.textContent = text; return c; };

// ---- Boot ------------------------------------------------------------------
await init();
wireLockScreen();
wireVaultScreen();
wireDialog();
wireFileLocker();
wireTotp();
updateNewStrength(); // show the "minimum N characters" prompt from the start
// One shared clock refreshes every visible 2FA code and its countdown.
setInterval(tick, 1000);
// Any interaction postpones auto-lock; the timer only arms while unlocked.
AUTOLOCK_ACTIVITY.forEach((ev) => document.addEventListener(ev, resetAutoLock, { passive: true }));

// Ctrl/Cmd+S saves the open vault (shows the overwrite modal), instead of the
// browser's "save page" dialog.
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s" && state.vault) {
    e.preventDefault();
    saveFile();
  }
});

// ===========================================================================
// Lock screen
// ===========================================================================
function wireLockScreen() {
  // Clicking the "Open vault" tab opens the OS file picker straight away (the
  // click is a user gesture); cancel and click the tab again to retry. The
  // other tabs just switch panes.
  $("tab-new").onclick = () => switchTab("new");
  $("tab-open").onclick = () => { switchTab("open"); openVaultPicker(); };
  $("tab-file").onclick = () => { switchTab("file"); $("file-input2").click(); };

  // Fallback path (browsers without the File System Access API): plain <input>.
  $("file-input").onchange = () => {
    if ($("file-input").files[0]) { state.fileHandle = null; loadFile($("file-input").files[0]); }
  };

  // The Unlock button only appears once a password has been typed.
  $("open-password").addEventListener("input", renderOpenPane);
  $("open-password").addEventListener("keydown", (e) => { if (e.key === "Enter") $("open-btn").click(); });
  $("open-btn").onclick = doUnlock;
  $("new-btn").onclick = doCreate;
  $("new-password").addEventListener("input", updateNewStrength);
  $("new-name").addEventListener("input", updateNameGhost);
  holdToReveal($("new-reveal-btn"), $("new-password"));
  // Enter on any of the Create-vault fields submits.
  for (const id of ["new-name", "new-password", "new-password2"]) {
    $(id).addEventListener("keydown", (e) => { if (e.key === "Enter") $("new-btn").click(); });
  }
  renderOpenPane();
  renderFilePane();
}

function switchTab(which) {
  for (const t of ["open", "new", "file"]) {
    $("tab-" + t).classList.toggle("active", which === t);
    $("pane-" + t).classList.toggle("hidden", which !== t);
  }
  lockError("");
  renderOpenPane();
  renderFilePane();
}

// Open-vault pane is staged: choose a file → the password field appears → the
// Unlock button appears once something is typed. (An in-memory snapshot after
// auto-lock also counts as "unlockable", with just the password.)
function renderOpenPane() {
  const hasFile = !!state.loadedBytes;
  const canUnlock = hasFile || !!state.snapshot;
  $("file-label").classList.toggle("hidden", !hasFile);
  $("open-password").classList.toggle("hidden", !canUnlock);
  const hasPw = $("open-password").value.length > 0;
  $("open-btn").classList.toggle("hidden", !(canUnlock && hasPw));
}

// Open a vault. Prefer the File System Access API so Save can later write back
// to the SAME file; fall back to a plain <input> where it isn't available.
async function openVaultPicker() {
  if (!window.showOpenFilePicker) { $("file-input").click(); return; }
  try {
    const [handle] = await window.showOpenFilePicker({
      // Custom MIME (unknown to the OS) so the filter shows only *.locked and
      // Windows doesn't expand a generic type into *.com/*.exe/*.bin. Old .psv
      // files can still be opened via the "All files" option.
      types: [{ description: "Vault", accept: { "application/x-psvault": [".locked"] } }],
      excludeAcceptAllOption: false,
    });
    state.fileHandle = handle;
    await loadFile(await handle.getFile());
  } catch {
    /* user cancelled the picker */
  }
}

async function loadFile(file) {
  state.loadedBytes = new Uint8Array(await file.arrayBuffer());
  state.filename = file.name;
  const label = $("file-label");
  label.textContent = "";
  label.append(fileNameEl(file.name)); // base (green) + extension (grey)
  const mod = fileModifiedText(file.lastModified);
  if (mod) {
    const meta = document.createElement("span");
    meta.className = "file-meta";
    meta.textContent = mod;
    label.appendChild(meta);
  }
  renderOpenPane(); // reveals the filename + password field, hides the prompt
  lockError("");
  $("open-password").focus(); // ready to type the master password immediately
}

// A filename split into a green base + a grey extension (e.g. "personal" + ".locked").
function fileNameEl(name) {
  const wrap = document.createElement("span");
  wrap.className = "fname";
  const dot = name.lastIndexOf(".");
  if (dot > 0) {
    wrap.append(document.createTextNode(name.slice(0, dot)));
    const ext = document.createElement("span");
    ext.className = "ext";
    ext.textContent = name.slice(dot);
    wrap.append(ext);
  } else {
    wrap.textContent = name;
  }
  return wrap;
}

// Human-readable last-modified time of a picked file ("" if unknown).
function fileModifiedText(ms) {
  if (!ms) return "";
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
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
  state.fileHandle = null; // no file yet — first Save picks a location
  state.dirty = true; // nothing saved yet
  enterVault();
}

// Preview the ".locked" extension in grey right after the typed vault name.
function updateNameGhost() {
  const ghost = $("new-name-ghost");
  ghost.textContent = "";
  const val = $("new-name").value;
  if (!val) return;
  ghost.append(document.createTextNode(val)); // transparent mirror (spacer)
  const suf = document.createElement("span");
  suf.className = "suffix";
  suf.textContent = ".locked";
  ghost.append(suf);
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
  $("file-input2").onchange = () => $("file-input2").files[0] && loadLockerFile($("file-input2").files[0]);
  $("file-password").addEventListener("input", renderFilePane);
  // Enter triggers whichever action is currently shown (Encrypt or Decrypt).
  $("file-password").addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const enc = $("encrypt-file-btn"), dec = $("decrypt-file-btn");
    if (!enc.classList.contains("hidden") && !enc.disabled) enc.click();
    else if (!dec.classList.contains("hidden") && !dec.disabled) dec.click();
  });
  $("encrypt-file-btn").onclick = encryptFile;
  $("decrypt-file-btn").onclick = decryptFile;
}

async function loadLockerFile(file) {
  state.lockerBytes = new Uint8Array(await file.arrayBuffer());
  state.lockerName = file.name;
  const label = $("file-label2");
  label.textContent = "";
  label.append(fileNameEl(file.name)); // base (green) + extension (grey)
  const meta = document.createElement("span");
  meta.className = "file-meta";
  const parts = [`${file.size} bytes`];
  const mod = fileModifiedText(file.lastModified);
  if (mod) parts.push(mod);
  meta.textContent = parts.join(" · ");
  label.appendChild(meta);
  renderFilePane(); // reveals the filename + password, hides the prompt
  lockError("");
  $("file-password").focus(); // ready to type the password immediately
}

// File-locker pane is staged like the open pane: choose a file → the password
// field appears → the matching action button appears once a password is typed.
// The extension decides which action shows: an already-encrypted file
// (".filelocked", or legacy ".locked"/".psv") -> Decrypt, anything else -> Encrypt.
function renderFilePane() {
  const enc = $("encrypt-file-btn"), dec = $("decrypt-file-btn"), desc = $("file-desc");
  const hasFile = !!state.lockerBytes;
  $("file-label2").classList.toggle("hidden", !hasFile);
  $("file-password").classList.toggle("hidden", !hasFile);
  if (!hasFile) {
    enc.classList.add("hidden");
    dec.classList.add("hidden");
    desc.classList.add("hidden");
    return;
  }

  const isLocked = /\.(filelocked|locked|psv)$/i.test(state.lockerName);
  const pwLen = $("file-password").value.length;
  // Encrypt needs a strong NEW password (min length); decrypt just needs the
  // existing one typed. The matching button only appears once that's satisfied.
  enc.classList.toggle("hidden", isLocked || pwLen < MIN_MASTER_PW);
  dec.classList.toggle("hidden", !isLocked || pwLen < 1);

  // Contextual description of what will happen with the chosen file.
  desc.classList.remove("hidden");
  desc.textContent = "";
  if (isLocked) {
    const orig = state.lockerName.replace(/\.(filelocked|locked|psv)$/i, "") || "the original";
    desc.append("This file is encrypted. Enter the password to decrypt it back to ");
    desc.append(codeEl(orig));
    desc.append(".");
  } else {
    desc.append("This file will be encrypted → you'll download ");
    desc.append(codeEl(state.lockerName + ".filelocked"));
    desc.append(`. Choose a master password (min ${MIN_MASTER_PW}).`);
  }
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
  updateNameGhost(); // clear the ".locked" preview
  $("new-password").value = "";
  $("new-password2").value = "";
  $("new-password").type = "password"; // back to hidden
  $("new-reveal-btn").querySelector("use").setAttribute("href", "#i-eye");
  updateNewStrength(); // resets the meter to the "minimum N characters" prompt
  setVaultName(state.filename);
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
  state.fileHandle = null;
  state.dirty = false;
  state.editingId = null;
  if ($("entry-dialog").open) $("entry-dialog").close();
  $("file-label").textContent = "";
  $("file-label").classList.add("hidden");
  $("open-password").value = "";
  $("vault-screen").classList.add("hidden");
  $("lock-screen").classList.remove("hidden");
  switchTab("open"); // re-renders the open pane (prompt vs. password vs. restore)
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

// Lock icon + the vault's filename (filename added as a text node, so it is safe).
function setVaultName(name) {
  const el = $("vault-name");
  el.innerHTML = icon("i-lock");
  el.append(" " + name);
}

function renderEntries() {
  const q = $("search").value.trim().toLowerCase();
  const list = $("entry-list");
  list.innerHTML = "";

  const items = state.vault.entries
    .filter((e) => !q || (e.title + e.username + e.url).toLowerCase().includes(q))
    .sort((a, b) => a.title.localeCompare(b.title));

  $("empty-note").classList.toggle("hidden", state.vault.entries.length !== 0);

  state.liveCodes = [];
  for (const e of items) {
    const li = document.createElement("li");
    li.className = "entry";
    const totpRow = e.totp
      ? `<div class="totp-line">
           <svg class="icon dim"><use href="#i-shield"/></svg>
           <code class="totp-code" data-role="code">••• •••</code>
           <span class="totp-ring" data-role="ring">30</span>
           <button class="small ghost" data-act="totp-copy" title="Copy 2FA code">${icon("i-copy")}</button>
           <button class="small ghost" data-act="totp-qr" title="Show 2FA QR">${icon("i-qr")}</button>
         </div>`
      : "";
    li.innerHTML = `
      <div class="info">
        <div class="title"></div>
        <div class="sub"></div>
        <code class="pw hidden"></code>
        ${totpRow}
      </div>
      <div class="actions">
        <button class="small ghost" data-act="reveal" title="Show password">${icon("i-eye")}</button>
        <button class="small" data-act="copy" title="Copy password">${icon("i-copy")}</button>
        <button class="small" data-act="edit" title="Edit">${icon("i-edit")}</button>
        <button class="small ghost" data-act="del" title="Delete">${icon("i-trash")}</button>
      </div>`;
    li.querySelector(".title").textContent = e.title || "(untitled)";
    li.querySelector(".sub").textContent = [e.username, e.url].filter(Boolean).join(" · ");
    const pwEl = li.querySelector(".pw");
    const revealBtn = li.querySelector('[data-act="reveal"]');
    revealBtn.onclick = () => {
      const nowHidden = pwEl.classList.toggle("hidden");
      pwEl.textContent = nowHidden ? "" : e.password;
      revealBtn.querySelector("use").setAttribute("href", nowHidden ? "#i-eye" : "#i-eye-off");
    };
    li.querySelector('[data-act="copy"]').onclick = () => copyPassword(e);
    li.querySelector('[data-act="edit"]').onclick = () => openDialog(e.id);
    li.querySelector('[data-act="del"]').onclick = () => deleteEntry(e.id);
    if (e.totp) {
      li.querySelector('[data-act="totp-copy"]').onclick = () => copyTotp(e.totp);
      li.querySelector('[data-act="totp-qr"]').onclick = () => showTotpQr(e.totp);
      state.liveCodes.push({
        codeEl: li.querySelector('[data-role="code"]'),
        ringEl: li.querySelector('[data-role="ring"]'),
        totp: e.totp,
      });
    }
    list.appendChild(li);
  }
  tick(); // paint codes immediately, don't wait up to a second
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
  let bytes;
  try {
    bytes = lock(JSON.stringify(state.vault), state.password);
  } catch (e) {
    return toast("Save failed: " + e);
  }

  // 1) We have a handle to the opened file -> overwrite it in place (after confirm).
  if (state.fileHandle) {
    if (!(await confirmOverwrite(state.filename))) return;
    try {
      if (!(await ensureWritePermission(state.fileHandle))) return toast("Write permission denied");
      await writeToHandle(state.fileHandle, bytes);
      state.dirty = false; updateDirty();
      toast("Saved");
    } catch (e) {
      toast("Save failed: " + e);
    }
    return;
  }

  // 2) No handle (new vault, first save) -> pick a location once, then remember it.
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: state.filename || "vault.locked",
        types: [{ description: "Vault", accept: { "application/octet-stream": [".locked"] } }],
      });
      await writeToHandle(handle, bytes);
      state.fileHandle = handle;
      state.filename = handle.name;
      setVaultName(state.filename);
      state.dirty = false; updateDirty();
      toast("Saved");
    } catch {
      /* user cancelled the save dialog */
    }
    return;
  }

  // 3) Fallback (no File System Access API) -> plain download.
  download(bytes, state.filename || "vault.locked");
  state.dirty = false; updateDirty();
  toast("Saved");
}

async function writeToHandle(handle, bytes) {
  const w = await handle.createWritable();
  await w.write(bytes);
  await w.close();
}

// Ensure we may write to the handle, prompting once if needed.
async function ensureWritePermission(handle) {
  if (!handle.queryPermission) return true;
  const opts = { mode: "readwrite" };
  if ((await handle.queryPermission(opts)) === "granted") return true;
  return (await handle.requestPermission(opts)) === "granted";
}

// Themed confirm modal for overwriting. Yes is focused so Enter confirms.
function confirmOverwrite(name) {
  return new Promise((resolve) => {
    const dlg = $("confirm-dialog");
    $("confirm-text").textContent = `Overwrite “${name}”?`;
    dlg.returnValue = "";
    dlg.showModal();
    $("confirm-yes").focus();
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "yes"), { once: true });
  });
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
  $("reveal-btn").querySelector("use").setAttribute("href", "#i-eye");
  $("totp-text").value = "";
  setDialogTotp(e?.totp || null); // deep-copy not needed: replaced wholesale on edit
  updateStrength();
  $("entry-dialog").showModal();
}

function toggleReveal(input, btn) {
  const reveal = input.type === "password";
  input.type = reveal ? "text" : "password";
  btn.querySelector("use").setAttribute("href", reveal ? "#i-eye-off" : "#i-eye");
}

// Press-and-hold to peek: the password shows only while the button is held down
// (pointerdown), and re-hides on release / leaving the button.
function holdToReveal(btn, input) {
  const use = btn.querySelector("use");
  // Switching input.type resets the caret to the start, so preserve it.
  const setType = (type) => {
    const { selectionStart: s, selectionEnd: e } = input;
    input.type = type;
    if (s !== null) {
      try { input.setSelectionRange(s, e); } catch { /* not selectable */ }
    }
  };
  const show = (e) => {
    e.preventDefault(); // keep focus in the input, suppress long-press menu
    setType("text");
    use.setAttribute("href", "#i-eye-off");
  };
  const hide = () => {
    setType("password");
    use.setAttribute("href", "#i-eye");
  };
  btn.addEventListener("pointerdown", show);
  ["pointerup", "pointerleave", "pointercancel"].forEach((ev) => btn.addEventListener(ev, hide));
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
// Staged feedback for the new master password:
//   0 chars      -> "Minimum 12 characters"
//   1..11 chars  -> "N characters left" (counting up to the minimum, no strength)
//   exactly 12   -> the strength word only
//   13+ chars    -> "N characters · <strength>"
function updateNewStrength() {
  const pw = $("new-password").value;
  const len = pw.length;
  const bar = $("new-strength-bar");
  const lbl = $("new-strength-label");

  if (len < MIN_MASTER_PW) {
    bar.style.width = "0";
    bar.style.background = "transparent";
    lbl.style.color = "var(--muted)";
    if (len === 0) {
      lbl.textContent = `Minimum ${MIN_MASTER_PW} characters`;
    } else {
      const left = MIN_MASTER_PW - len;
      lbl.textContent = `${left} character${left === 1 ? "" : "s"} left`;
    }
    return;
  }

  // At/above the minimum: show strength; add the count once past 12.
  const { label, color, pct } = scorePassword(pw);
  bar.style.width = pct + "%";
  bar.style.background = color;
  lbl.style.color = color;
  lbl.textContent = len > MIN_MASTER_PW ? `${len} characters · ${label}` : label;
}

function applyDialog() {
  const now = Math.floor(Date.now() / 1000);
  const data = {
    title: $("f-title").value.trim(),
    username: $("f-username").value,
    password: $("f-password").value,
    url: $("f-url").value.trim(),
    notes: $("f-notes").value,
    totp: state.editingTotp || null, // null serializes away (serde skips None)
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

// ===========================================================================
// Two-factor (TOTP): import a setup QR / key, show live codes, export a QR
// ===========================================================================
function wireTotp() {
  $("totp-remove").onclick = () => setDialogTotp(null);
  $("totp-paste-btn").onclick = pasteQrFromClipboard;
  $("totp-file-btn").onclick = () => $("totp-file-input").click();
  $("totp-file-input").onchange = () => {
    const f = $("totp-file-input").files[0];
    if (f) importTotpImage(f);
    $("totp-file-input").value = ""; // allow re-picking the same file
  };
  $("totp-text").addEventListener("input", onTotpText);
  // Ctrl+V of an image anywhere in the dialog imports the QR (the "crop from a
  // page and paste" flow: Win+Shift+S puts a cropped screenshot on the clipboard).
  $("entry-dialog").addEventListener("paste", onDialogPaste);
}

// Show either the "import" state or the live-preview state for the dialog.
function setDialogTotp(totp) {
  state.editingTotp = totp;
  const has = !!totp;
  $("totp-empty").classList.toggle("hidden", has);
  $("totp-set").classList.toggle("hidden", !has);
  $("totp-remove").classList.toggle("hidden", !has);
  totpError("");
  if (has) {
    $("totp-dlg-label").textContent =
      [totp.issuer, totp.account].filter(Boolean).join(" · ") || "TOTP";
    $("totp-text").value = "";
  }
  tick(); // refresh the preview code now
}

function onDialogPaste(e) {
  for (const it of e.clipboardData?.items || []) {
    if (it.type.startsWith("image/")) {
      e.preventDefault(); // don't also drop the image into a text field
      importTotpImage(it.getAsFile());
      return;
    }
  }
  // No image on the clipboard — let a normal text paste happen.
}

// The "Paste QR image" button: pull an image off the clipboard explicitly
// (needs the async Clipboard API; Ctrl+V via onDialogPaste is the fallback).
async function pasteQrFromClipboard() {
  totpError("");
  try {
    if (!navigator.clipboard?.read)
      throw new Error("Clipboard images aren't available here — use Ctrl+V or “Image file…”.");
    for (const it of await navigator.clipboard.read()) {
      const type = it.types.find((t) => t.startsWith("image/"));
      if (type) return void importTotpImage(await it.getType(type));
    }
    throw new Error("No image on the clipboard. Screenshot the QR (Win+Shift+S) first.");
  } catch (err) {
    totpError(errText(err));
  }
}

async function importTotpImage(blob) {
  totpError("");
  try {
    const totp = await totpFromImage(blob);
    fillTotpMeta(totp);
    setDialogTotp(totp);
    toast("2FA added from QR");
  } catch (err) {
    totpError(errText(err));
  }
}

// Draw the image to a canvas, hand the raw pixels to the Rust QR decoder, then
// interpret the decoded text as a 2FA payload.
async function totpFromImage(blob) {
  const bitmap = await createImageBitmap(blob);
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close?.();
  const { data, width, height } = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const text = decode_qr(new Uint8Array(data.buffer), width, height); // throws if no QR
  return totpFromText(text);
}

// Turn decoded text (an otpauth:// URI, or a bare Base32 key) into a Totp object.
function totpFromText(text) {
  const s = String(text).trim();
  if (s.toLowerCase().startsWith("otpauth://")) {
    return JSON.parse(parse_otpauth(s)); // throws with a reason on a bad URI
  }
  // Otherwise treat it as a raw setup key; validate it by generating a code.
  const secret = s.replace(/\s+/g, "");
  totp_code(secret, "SHA1", 6, 30, Date.now() / 1000); // throws if not Base32
  return { secret, issuer: "", account: "", algorithm: "SHA1", digits: 6, period: 30 };
}

function onTotpText() {
  const s = $("totp-text").value.trim();
  if (!s) return totpError("");
  try {
    const totp = totpFromText(s);
    fillTotpMeta(totp);
    setDialogTotp(totp);
  } catch (err) {
    // A malformed otpauth link is worth flagging; a half-typed key is not.
    totpError(s.toLowerCase().startsWith("otpauth://") ? errText(err) : "");
  }
}

// Fill in blank issuer/account from the entry being edited, so an export QR and
// the list label read nicely even when only a bare key was pasted.
function fillTotpMeta(totp) {
  if (!totp.issuer) totp.issuer = $("f-title").value.trim();
  if (!totp.account) totp.account = $("f-username").value.trim();
}

// Refresh every visible code + countdown. Cheap no-op when nothing shows a code.
function tick() {
  const now = Date.now() / 1000;
  for (const item of state.liveCodes) paintTotp(item, now);
  if ($("entry-dialog").open && state.editingTotp) {
    paintTotp(
      { codeEl: $("totp-dlg-code"), ringEl: $("totp-dlg-ring"), totp: state.editingTotp },
      now
    );
  }
}

function paintTotp({ codeEl, ringEl, totp: t }, now) {
  try {
    const code = totp_code(t.secret, t.algorithm || "SHA1", t.digits || 6, t.period || 30, now);
    codeEl.textContent = groupCode(code);
    codeEl.dataset.code = code;
  } catch {
    codeEl.textContent = "invalid key";
    codeEl.dataset.code = "";
  }
  const period = t.period || 30;
  const remaining = period - (Math.floor(now) % period);
  ringEl.textContent = remaining;
  ringEl.classList.toggle("soon", remaining <= 5);
}

// "123456" -> "123 456", "12345678" -> "1234 5678".
function groupCode(code) {
  const half = Math.ceil(code.length / 2);
  return code.slice(0, half) + " " + code.slice(half);
}

async function copyTotp(totp) {
  try {
    const code = totp_code(totp.secret, totp.algorithm, totp.digits, totp.period, Date.now() / 1000);
    await navigator.clipboard.writeText(code);
    toast("2FA code copied");
  } catch {
    toast("Copy failed");
  }
}

// Show the account's own setup QR so it can be added to a phone / another app.
function showTotpQr(totp) {
  try {
    $("qr-dialog-svg").innerHTML = totp_qr_svg(JSON.stringify(totp)); // SVG is generated by us
    $("qr-dialog-label").textContent =
      [totp.issuer, totp.account].filter(Boolean).join(" · ") || "TOTP";
    $("qr-dialog").showModal();
  } catch (e) {
    toast("QR failed: " + e);
  }
}

function totpError(msg) { $("totp-error").textContent = msg; }
function errText(err) { return String(err?.message || err); }

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
