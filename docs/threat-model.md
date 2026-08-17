# Threat Model

Status: baseline MVP  
Rujukan: [`SPEC.md`](SPEC.md), [`auth-design.md`](auth-design.md), [`key-rotation-design.md`](key-rotation-design.md)

## Aset dan trust boundary

Aset utama adalah plaintext configuration, password/TOTP material, KEK/DEK, session dan recent-auth state, audit trail, database/backup integrity, serta kebenaran status applied. Boundary utama: browser pengguna; HTTPS reverse proxy/access layer; container ConfigDeck; volume data/backup; secret mount; dan deployment platform tujuan yang dioperasikan manual.

Asumsi: host/container administrator tetap merupakan pihak berprivilege tinggi. Encryption at rest melindungi database/backup yang dicuri tanpa KEK, bukan host yang sudah dikuasai saat aplikasi dapat membaca KEK dan memory plaintext.

## Threat register

| Ancaman | Dampak | Kontrol wajib | Residual/response |
|---|---|---|---|
| SQLite atau backup dicuri | Seluruh nilai dan history terekspos | Semua value AEAD; per-environment DEK; KEK di luar DB; TOTP seed terenkripsi; hashed session tokens; backup KEK terpisah | Metadata, key names, email, dan audit masih terlihat; rotate affected credentials bila KEK ikut dicurigai |
| Contributor bypass UI/call API langsung | Restricted plaintext atau operasi apply | Policy backend yang sama untuk UI/API; service scope; no decrypt before auth; negative authorization tests | Audit denial secara terbatas tanpa membocorkan resource existence |
| Session Operator/Admin dicuri | Reveal/export/admin action | Secure HttpOnly SameSite cookie; hashed token DB; idle/absolute expiry; session rotation/revocation; recent password+TOTP; no-store | Recent-auth window menyisakan risiko singkat; revoke sessions dan audit activity |
| XSS | Pencurian plaintext yang sedang tampil/action sebagai user | Askama auto-escape; CSP tanpa inline script; local assets; output encoding; sanitasi/validasi URL; tidak simpan secret di browser storage | Plaintext yang sengaja direveal tetap bisa dibaca script jika XSS lolos; prioritaskan patch dan credential rotation |
| CSRF | Perubahan/request/export atas nama user | Per-session random CSRF token, server-stored hash, constant-time verify, unsafe-method enforcement, SameSite, Origin check defense-in-depth | XSS dapat melewati CSRF; ditangani oleh kontrol XSS |
| Brute force/password spraying | Account takeover/DoS | Argon2id; per-account exponential backoff; per trusted client rate limit; generic error; no hard lockout berbasis count; TOTP untuk privileged roles | Distributed attempts mungkin lolos IP limit; monitor LOGIN_FAILED tanpa password/code |
| Log leakage | Secret tersalin ke logs/APM | No request body; field allowlist; redaction; route template bukan raw sensitive URL; error sanitization; tests | Operator harus mengontrol platform log access dan retention |
| Browser/proxy cache leakage | Secret tersimpan/dibagikan | `no-store`, `Pragma: no-cache`, no secret in GET/query, reveal via POST, clipboard only on explicit action, no local/session storage | OS clipboard/history berada di luar kontrol aplikasi; UX memperingatkan Operator |
| Ciphertext/nonce/AAD diubah atau dipindah | Corruption/substitution | ChaCha20-Poly1305 tag; canonical stable AAD binds entity IDs, field purpose, version, DEK version; transaction checks | Availability loss tetap mungkin; fail closed, alert, restore tested backup |
| Master key hilang | Data permanen tidak dapat dibuka | Fail-fast; separately protected/off-host KEK backup; tested restore; key fingerprint validation | Tidak ada recovery cryptographic tanpa KEK; dokumentasikan sebagai irreversible |
| Master key compromised | Semua wrapped DEK dapat dibuka | Secret file permissions; read-only mount; no DB/log; rewrap after new KEK; rotate affected DEKs/credentials based on incident scope | KEK rewrap saja tidak menghapus plaintext exposure yang telah terjadi |
| DEK compromised | Satu environment + history terekspos | Per-environment DEK; DEK rotation re-encrypts current/history/proposals; destroy retired wrapped material | Rotate actual external credentials juga; crypto rotation tidak membatalkan credential lama |
| Container filesystem/process access | KEK/memory/database exposure | Non-root; read-only rootfs; dropped caps; no-new-privileges; minimal image; writable mounts limited; host patching | Root/host compromise berada di luar app boundary; rebuild and rotate secrets |
| Malicious `.env` import | Parser confusion, resource exhaustion, XSS, overwrite | Size/line/key/value limits; strict parser; duplicate detection; preview; default restricted; escaped output; atomic import; no interpolation/command execution | Valid but dangerous values can still break target app; Operator reviews preview |
| Malicious organization logo | Stored XSS, parser abuse, tracking, memory/database growth | Authenticated Administrator-only setup; PNG/WebP allowlist; 256 KiB limit; MIME plus magic-byte validation; no remote URL; no user SVG; CSP local images | Image decoder bugs remain browser-controlled; keep browser patched and remove suspect logo through an audited future settings flow |
| Reverse-proxy spoofing | Bypass rate limit/audit identity | Trust forwarded headers only from configured proxy CIDR/count; otherwise use peer IP; reject malformed chains | Proxy misconfiguration remains operational risk; startup validation and docs |
| IDOR/service enumeration | Cross-service access | Object lookup scoped through policy; indistinguishable 404 where appropriate; UUID; tests | Operators intentionally see all services |
| Replay/double apply/stale preview | Wrong current config/status | CSRF; idempotent terminal transition; DB transaction; `base_variable_version`; preview fingerprint/version revalidation at apply | Manual deployment-platform update can still diverge; ConfigDeck records known state only |
| Concurrent/batch partial apply | Ambiguous registry | Single write transaction for selected change set; validate all items first; rollback on any failure; audit in same transaction | SQLite write lock may delay request; busy timeout and clear retry UX |
| Backup/restore path traversal | Arbitrary read/write | Server-generated strict filename; basename identifier only; canonical allowlisted `/backup`; no browser-provided path in SQL | Volume operator can alter files; checksum/integrity and offline validation |
| Restore audit disappearance | Untraceable restore | External non-secret restore-intent marker; startup validation; first committed `RESTORE_BACKUP`; delete marker only afterward | A host admin can delete marker; host trust is explicit |
| Audit tampering | Hilangnya accountability | Append-only application API, DB triggers against update/delete, least-privilege file access, off-host backup/log export recommended | SQLite owner/host admin can replace DB; cryptographic audit chaining is post-MVP |
| TOTP replay/time skew | Privileged login abuse | Accept narrow window, store last accepted timestep, reject reuse, rate limit, encrypt seed | Clock correctness required; monitor NTP/host time |
| Login/account enumeration | Targeting accounts | Generic response/timing discipline; normalized email; rate limiter writes indistinguishable externally | Timing cannot be perfectly equal; test gross differences |

## Abuse cases yang wajib dites

- Contributor meminta restricted value melalui HTML, HTMX, API, export, history, error, dan malformed content negotiation.
- User berakses service A mengganti ID/path/body menjadi service B.
- Request di-approve lalu variable berubah sebelum apply; apply harus gagal tanpa partial write.
- Ciphertext, nonce, AAD identifier, atau `dek_version` dimodifikasi; decrypt harus gagal tertutup.
- CSRF token hilang/salah/replay dari session lain; unsafe request gagal.
- Session lama dipakai setelah password/role/access/TOTP berubah; session invalid.
- Previous TOTP timestep dipakai ulang; login/recent-auth gagal.
- `.env` berisi duplicate key, invalid key, NUL, newline kompleks, payload terlalu besar, dan markup; tidak ada execution/XSS/overwrite diam-diam.
- Organization logo menyamar sebagai PNG/WebP, memakai MIME lain, kosong, atau melebihi batas; setup ditolak tanpa completion/audit sukses.
- Forwarded headers dari peer tidak tepercaya tidak memengaruhi audit/rate limit identity.
- Backup identifier mengandung separator, traversal, Unicode confusable, atau symlink target; ditolak.

## Incident notes

KEK/DEK rotation bukan pengganti rotasi credential di sistem tujuan. Jika plaintext mungkin terekspos, putar credential eksternal lalu update deployment platform dan ConfigDeck. Jika KEK hilang tanpa backup, data terenkripsi tidak dapat dipulihkan. Jika host aktif dikompromikan, anggap seluruh environment yang dapat didecrypt oleh proses ikut terdampak.
