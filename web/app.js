import init, {
  unlock, lock, empty_vault_json, generate_password, lock_file, unlock_file,
} from "./pkg/vault_wasm.js";

// ---- App state -------------------------------------------------------------
const state = {
  vault: null,        // { schema, entries: [] }
  password: null,     // master password, kept only in memory while unlocked
  filename: "vault.psv",
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
  $("tab-open").onclick = () => switchTab("open");
  $("tab-new").onclick = () => switchTab("new");
  // Clicking the tab is a user gesture, so we can open the OS file picker right away.
  $("tab-file").onclick = () => { switchTab("file"); $("file-input2").click(); };

  const fileInput = $("file-input"), drop = $("file-drop");
  fileInput.onchange = () => fileInput.files[0] && loadFile(fileInput.files[0]);
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("drag"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("drag"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault(); drop.classList.remove("drag");
    if (e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]);
  });

  $("open-password").addEventListener("keydown", (e) => { if (e.key === "Enter") $("open-btn").click(); });
  $("open-btn").onclick = doUnlock;
  $("new-btn").onclick = doCreate;
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
  $("file-label").textContent = file.name;
  $("file-drop").classList.add("loaded");
  $("open-btn").disabled = false;
  lockError("");
}

function doUnlock() {
  const pw = $("open-password").value;
  // Unlock a picked file, or — if none — restore an unsaved snapshot from a
  // previous lock (both are encrypted with the same master password).
  const bytes = state.loadedBytes || state.snapshot;
  if (!bytes) return lockError("Сначала выбери файл хранилища.");
  if (!pw) return lockError("Введи мастер-пароль.");
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
    if (restored) toast("Восстановлено несохранённое состояние");
  } catch (e) {
    lockError(String(e));
  }
}

function doCreate() {
  const pw = $("new-password").value, pw2 = $("new-password2").value;
  if (pw.length < 4) return lockError("Пароль слишком короткий.");
  if (pw !== pw2) return lockError("Пароли не совпадают.");
  state.vault = JSON.parse(empty_vault_json());
  state.password = pw;
  state.filename = "vault.psv";
  state.dirty = true; // nothing saved yet
  enterVault();
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
  $("file-label2").textContent = `${file.name} (${file.size} байт)`;
  $("file-drop2").classList.add("loaded");
  updateLockerButtons();
  lockError("");
  $("file-password").focus(); // ready to type the password immediately
}

// The file's extension decides the operation: ".locked" -> decrypt, anything
// else -> encrypt. Only the matching button is shown, and only once a file is
// selected and a password is typed.
function updateLockerButtons() {
  const enc = $("encrypt-file-btn"), dec = $("decrypt-file-btn");
  if (!state.lockerBytes) {
    enc.classList.add("hidden");
    dec.classList.add("hidden");
    return;
  }
  const isLocked = /\.locked$/i.test(state.lockerName);
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
    download(out, state.lockerName + ".locked");
    toast("Файл зашифрован");
  } catch (e) { lockError(String(e)); }
}

function decryptFile() {
  const pw = $("file-password").value;
  if (!state.lockerBytes || !pw) return;
  try {
    const out = unlock_file(state.lockerBytes, pw); // throws on wrong password
    // Strip our encrypted-file suffix (".locked", or legacy ".psv") to restore
    // the original name, e.g. "AndriiSukhodieiev.pfx.locked" -> ".pfx".
    const name = state.lockerName.replace(/\.(locked|psv)$/i, "") || "decrypted";
    download(out, name);
    toast("Файл расшифрован");
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
  $("new-password").value = "";
  $("new-password2").value = "";
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
  $("file-label").textContent = "Выбрать файл хранилища…";
  $("file-drop").classList.remove("loaded");
  $("open-btn").disabled = !state.snapshot; // snapshot can be unlocked with just a password
  $("open-password").value = "";
  $("vault-screen").classList.add("hidden");
  $("lock-screen").classList.remove("hidden");
  switchTab("open");
  updateRestoreNote();
  if (reason === "auto") toast("Заблокировано по бездействию");
}

// Arm/refresh the inactivity timer. No-op while locked or when set to "выкл".
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
        <button class="small ghost" data-act="reveal" title="Показать пароль">👁</button>
        <button class="small" data-act="copy">Копировать</button>
        <button class="small" data-act="edit">✏️</button>
        <button class="small ghost" data-act="del">🗑</button>
      </div>`;
    li.querySelector(".title").textContent = e.title || "(без названия)";
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
    toast("Пароль скопирован");
  } catch {
    toast("Не удалось скопировать");
  }
}

function deleteEntry(id) {
  const e = state.vault.entries.find((x) => x.id === id);
  if (!confirm(`Удалить «${e?.title || "запись"}»?`)) return;
  state.vault.entries = state.vault.entries.filter((x) => x.id !== id);
  markDirty();
  renderEntries();
}

async function saveFile() {
  try {
    const bytes = lock(JSON.stringify(state.vault), state.password);
    download(bytes, state.filename || "vault.psv");
    state.dirty = false;
    updateDirty();
    toast("Сохранено");
  } catch (e) {
    toast("Ошибка сохранения: " + e);
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
  $("dialog-title").textContent = id ? "Редактировать запись" : "Новая запись";
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

// Rough entropy estimate: length × log2(character-pool size).
function updateStrength() {
  const pw = $("f-password").value;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  const bits = pw ? pw.length * Math.log2(pool || 1) : 0;

  let label = "", color = "transparent";
  if (bits > 0 && bits < 40) { label = "Слабый"; color = "#ff5c5c"; }
  else if (bits < 60) { label = "Средний"; color = "#ffb020"; }
  else if (bits < 80) { label = "Хороший"; color = "#43c47a"; }
  else if (bits >= 80) { label = "Отличный"; color = "#2fe08a"; }

  const bar = $("strength-bar");
  bar.style.width = Math.min(100, Math.round(bits)) + "%"; // ~100 bits fills the bar
  bar.style.background = color;
  const lbl = $("strength-label");
  lbl.textContent = label;
  lbl.style.color = color;
}

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
