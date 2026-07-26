# Password Store

A local, encrypted vault for passwords and files. One master password protects
one self-contained file that you can carry on a USB stick or keep in the cloud —
your data never leaves the device in the clear.

## How it works

```
master password ──Argon2id(salt)──▶ 32-byte key ──XChaCha20-Poly1305(nonce)──▶ .psv file
```

A single Rust crypto crate (`vault-core`) is reused across every front-end:

```
vault-core (Rust)
   ├── vault-wasm  → WASM
   │     ├── web/        → web page (open in a browser)
   │     └── extension/  → Chrome extension (toolbar button, offline)
   └── (later)     → native desktop (tauri)
```

## Layout

| Path | What it is |
|---|---|
| `crates/vault-core` | file format + encryption, covered by tests |
| `crates/vault-wasm` | thin WASM bindings (unlock / lock / file locker / password generator) |
| `web/` | UI: `index.html`, `style.css`, `app.js` |
| `web/pkg/` | built WASM (generated, do not edit) |
| `extension/` | Chrome extension: `manifest.json`, `background.js`, `icons/` + synced UI |

## Development

```powershell
# core tests
cargo test

# rebuild WASM after editing Rust
./build.ps1

# run the UI locally (no-cache dev server)
./run.ps1        # opens http://127.0.0.1:8765/

# build the Chrome extension (into ./extension)
./build-ext.ps1
```

## Chrome extension

No autofill — it is just the packaged UI, so it requires **zero permissions**
and review is trivial. You don't need the store for personal use.

Install (developer mode):

1. `./build-ext.ps1` — assembles the `extension/` folder
2. Open `chrome://extensions`
3. Enable **Developer mode** (top right)
4. **Load unpacked** → select the `extension/` folder
5. Clicking the toolbar icon opens the vault in a dedicated tab

After editing code: run `./build-ext.ps1` again, then click ↻ on the extension card.

> Works on desktop Chrome (and Edge/Brave). Mobile Chrome does not support
> extensions — use the web version from `web/` there.

## Features

- **Vault**: entries with title, username, password, URL, notes; search
- **Password generator** with length / symbols options and a strength meter
- **Show / hide** passwords in the list and in the editor
- **Auto-lock** on inactivity (1 / 5 / 15 min / off); unsaved edits are kept as an
  encrypted in-memory snapshot and restored with the master password
- **File locker**: encrypt/decrypt *any* file under the master password

## Requirements

- Rust 1.96+, target `wasm32-unknown-unknown`
- `wasm-pack`
- Python 3 (only for the local dev server)

## `.psv` file format (v1)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `PSV1` |
| 4 | 1 | format version |
| 5 | 12 | Argon2 params (m/t/p, LE u32) |
| 17 | 16 | salt |
| 33 | 24 | nonce (XChaCha20) |
| 57 | … | ciphertext + Poly1305 tag |

The header is authenticated as AAD — tampering with the KDF parameters is
rejected on decrypt.

## File locker

The "🔒 File" tab on the lock screen encrypts/decrypts **any** file under the
master password, using the same crypto. Handy for backing up sensitive files
(keys, `.pfx` signatures) to a cloud/messenger that has no end-to-end encryption.

- **Encrypt:** pick a file → password → download `name.locked`
- **Decrypt:** pick a `.locked` file → same password → get the original back

Encrypted files get a `.locked` suffix (vs `.psv` for entry vaults). Everything
stays local. Core: `seal_bytes` / `open_bytes`; WASM: `lock_file` / `unlock_file`.

## Roadmap

- [x] Chrome extension wrapper (`manifest.json` + icons over the UI)
- [x] Auto-lock on inactivity
- [x] Password strength meter + generator options (length / symbols)
- [x] Show / hide passwords
- [x] File locker (encrypt any file)
- [ ] Light / dark theme toggle
- [ ] (opt.) publish to the Chrome Web Store (or Unlisted)
- [ ] (opt.) native desktop via tauri

## License

[MIT](LICENSE) © 2026 gravitymir
