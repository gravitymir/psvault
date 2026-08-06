# Password Store

A local, encrypted vault for passwords and files. One master password protects
one self-contained file that you can carry on a USB stick or keep in the cloud —
your data never leaves the device in the clear.

## How it works

```
master password ──Argon2id(salt)──▶ 32-byte key ──XChaCha20-Poly1305(nonce)──▶ .locked file
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
| `crates/vault-core` | file format + encryption + TOTP (`totp` module), covered by tests |
| `crates/vault-wasm` | thin WASM bindings (unlock / lock / file locker / generator / QR + TOTP) |
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
- **Two-factor codes (TOTP)**: import a site's 2FA setup QR (or key) and generate
  the rotating 6-digit codes yourself — no phone authenticator app needed

## Requirements

- Rust 1.96+, target `wasm32-unknown-unknown`
- `wasm-pack`
- Python 3 (only for the local dev server)

## File format (v1, `.locked`)

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

- **Encrypt:** pick a file → password → download `name.filelocked`
- **Decrypt:** pick a `.filelocked` file → same password → get the original back

Vaults use `.locked`, locked files use `.filelocked` — same on-disk format, the
extension just tells them apart. Everything stays local. Core: `seal_bytes` /
`open_bytes`; WASM: `lock_file` / `unlock_file`.

## Two-factor codes (TOTP)

Replace a phone authenticator app: attach a service's 2FA secret to its entry and
the vault generates the same rotating codes (RFC 6238). The secret is stored
encrypted inside the vault like everything else.

**Import** — open an entry (Add/Edit) and, under *Two-factor code*:

- Screenshot the site's setup QR (Windows: **Win+Shift+S** for a cropped region),
  then **Paste QR image** — or just **Ctrl+V** anywhere in the dialog. The QR is
  decoded locally and its `otpauth://` secret is stored.
- Or paste the `otpauth://…` link / the Base32 setup key the site shows instead.

The list then shows a live 6-digit code with a countdown; the copy button puts the
current code on the clipboard.

**Export** — the QR button on a 2FA entry shows its own `otpauth://` QR, so the
same account can be added to a phone or another authenticator. (Whoever scans it
gets the secret — treat it like the password.)

Nothing is transmitted: QR decode/encode and code generation all run in the local
WASM. Core: `vault_core::totp` (Base32, HOTP/TOTP, `otpauth://` parse/build);
WASM: `decode_qr` / `parse_otpauth` / `totp_code` / `totp_qr_svg`.

> The **Paste QR image** button uses the async clipboard API (may prompt / be
> unavailable in the zero-permission extension); **Ctrl+V** and **Image file…**
> always work.

## Roadmap

- [x] Chrome extension wrapper (`manifest.json` + icons over the UI)
- [x] Auto-lock on inactivity
- [x] Password strength meter + generator options (length / symbols)
- [x] Show / hide passwords
- [x] File locker (encrypt any file)
- [x] TOTP 2FA authenticator (import setup QR / key, generate codes)
- [ ] Light / dark theme toggle
- [ ] (opt.) publish to the Chrome Web Store (or Unlisted)
- [ ] (opt.) native desktop via tauri

## License

[MIT](LICENSE) © 2026 gravitymir
