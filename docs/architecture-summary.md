# Architecture Summary

Status: baseline desain pra-implementasi  
Source of truth: [`SPEC.md`](SPEC.md)

## Tujuan dan batas sistem

ConfigDeck adalah portal internal untuk mencatat konfigurasi environment dan mengelola workflow perubahan manual menuju deployment platform apa pun. ConfigDeck tidak melakukan deployment, tidak bergantung pada vendor tertentu, dan bukan secret manager umum. Status `APPLIED` hanya terjadi setelah Operator secara eksplisit menyatakan hasil yang disalin sudah diterapkan pada platform tujuan.

Pada database baru, bootstrap tetap membuat Administrator secara fail-closed dari deployment environment. Administrator wajib menyelesaikan TOTP, mengganti initial password, lalu menjalani wizard organisasi terautentikasi sebelum route aplikasi normal tersedia. Wizard menyimpan nama organisasi dan optional logo PNG/WebP tervalidasi di SQLite; remote URL dan user-uploaded SVG tidak dirender. Setelah onboarding, `Users & Access` menjadi entry point Administrator untuk membuat account role tetap dan mengelola akses Contributor.

Account baru wajib mengganti initial password setelah TOTP enrollment yang diwajibkan. Role/status/TOTP reset membutuhkan recent-auth Administrator, menaikkan auth version, mencabut session target, dan menjaga minimal satu active Administrator.

## Bentuk deployment

Satu proses Rust/Axum melayani SSR HTML, HTMX, static assets lokal, dan internal REST API. Proses yang sama menjalankan business logic, crypto, audit, backup, dan maintenance. SQLite berada di `/data/configdeck.db`; snapshot konsisten berada di volume terpisah `/backup`; KEK dibaca terutama dari Docker secret. Tidak ada Node runtime, Redis, message queue, worker, atau microservice.

```text
Browser -> trusted HTTPS reverse proxy/access layer -> ConfigDeck (Axum)
                                                    |-> SQLite /data
                                                    |-> backup /backup
                                                    `-> KEK files /run/secrets (read-only)
ConfigDeck -> Operator clipboard -> Deployment Platform UI (manual, di luar trust boundary)
```

## Modul aplikasi

- `config`: konfigurasi tervalidasi, secret-file loading, trusted proxy policy.
- `db`: pool SQLite konservatif, migration, transaction helpers, readiness.
- `auth`: password Argon2id, login throttling, TOTP, hashed server-side session, CSRF, recent-auth.
- `crypto`: AEAD, envelope encryption, AAD canonical, KEK/DEK rotation.
- `users`: user, role, activation, service access, session revocation.
- `services` dan `environments`: metadata serta ownership hierarchy.
- `variables`: encrypted current state, versions, import/parser, dotenv renderer.
- `requests`: change set, review, fulfillment, preview, atomic apply.
- `audit`: append-only security/business events dan filtered viewer Operator/Administrator yang hanya merender metadata allowlist.
- `operations`: backup, restore intent, dan startup restore reconciliation.
- `rotations`: KEK re-wrap/TOTP re-encryption, synchronous resumable DEK batches, verification, dan maintenance write guard.
- `web`: route/handler SSR + API, Askama templates, local assets.

Presentation preferences such as theme, App catalog Grid/List, and collapsed sidebar are browser-local and contain no identity, authorization, configuration value, or workflow state. SSR remains usable without JavaScript; JavaScript only progressively moves contextual breadcrumbs into the top bar and enhances presentation controls.

Handler hanya melakukan parsing, policy entry check, dan response mapping. Business service memegang invariant dan transaction boundary. Repository mengisolasi SQLx query. Crypto menerima identifier/version eksplisit untuk membentuk AAD; caller tidak dapat memilih AAD arbitrer.

## Data dan consistency boundary

- ID adalah UUID acak yang disimpan sebagai canonical lowercase `TEXT`.
- Waktu disimpan sebagai RFC 3339 UTC `TEXT`.
- Semua environment value—public maupun restricted—dienkripsi.
- Satu environment memiliki tepat maksimum satu active DEK, ditegakkan partial unique index.
- Current variable baru berubah dalam transaksi `Mark Applied`; request yang belum applied hanya memengaruhi preview hasil.
- Pembuatan service baru secara atomik membuat tiga environment standar—`Development`, `Staging`, dan `Production`—beserta active DEK masing-masing. Custom environment tetap tersedia sebagai kebutuhan lanjutan.
- Satu `change_requests` adalah change set dan memiliki satu atau banyak `change_request_items`.
- Item menyimpan `base_variable_version`; apply gagal aman jika current version berubah sejak request dibuat/rebase terakhir.
- Apply mengunci write transaction, memvalidasi seluruh set, menulis versions/current rows, status, dan audit secara atomik.
- SQLite menjalankan `foreign_keys=ON`, WAL, busy timeout, dan pool kecil. Nilai final ditentukan saat implementasi dan benchmark.

## Request state machine

```text
submit lengkap -> REQUESTED --approve--> READY_TO_APPLY --mark applied--> APPLIED
submit kurang  -> NEEDS_INPUT --approve (tetap) / fulfill semua--> READY_TO_APPLY
REQUESTED | NEEDS_INPUT | READY_TO_APPLY --reject--> REJECTED
```

Jika fulfillment selesai sebelum approval, status menjadi `REQUESTED`; jika approval sudah dicatat, menjadi `READY_TO_APPLY`. Status terminal tidak dapat dibuka kembali. Preview resulting `.env` hanya tersedia saat `READY_TO_APPLY` dan setelah pengecekan recent-auth/capability.

## Request path dan security middleware

Urutan konseptual: request ID → trusted proxy client identity → tracing metadata aman → security headers → body/timeout limits → session lookup → CSRF untuk unsafe methods → route capability/service-scope check → recent-auth bila sensitif → handler. Response yang pernah berisi plaintext restricted value selalu `Cache-Control: no-store` dan `Pragma: no-cache`.

HTML di-escape Askama. Tidak ada inline script; Clipboard API berada pada JS lokal. API dan UI memanggil policy/business service yang sama agar tidak terjadi authorization drift.

Route browser merender kegagalan yang aman sebagai halaman HTML ramah pengguna; route `/api/*` mempertahankan JSON terstruktur. Pesan browser tidak pernah memuat detail database, crypto, atau error internal. Import preview tidak memantulkan plaintext: review besar dibantu pencarian key dan bulk visibility yang hanya memengaruhi baris terlihat, dengan `restricted` tetap menjadi default fail-safe.

Katalog `Configurations` tetap menerima daftar service yang sudah difilter authorization backend. JavaScript lokal hanya melakukan search, sort, dan perubahan Grid/List atas row yang sudah dirender; tanpa JavaScript daftar tetap tersedia sebagai grid. Preference `configdeck.serviceView` dan theme adalah state presentasi non-sensitif, tidak memuat identifier, value, atau authorization state.

Entry App membuka workspace perbandingan lintas environment. Query workspace hanya memilih key, presence, visibility, type, version, deployment status, dan keberadaan request nonterminal setelah service-scope authorization; encrypted value, nonce, ciphertext, dan plaintext tidak ikut dipilih. Search/filter/sort serta row expansion hanya menata metadata terotorisasi yang sudah dirender. Link tiap cell kembali ke halaman environment yang tetap menegakkan masking, reveal capability, dan recent-auth existing. Sidebar `Configurations` tetap direct link ke katalog; matrix menampilkan status dot ringkas dan hover/focus hint pada konteks yang relevan.

Topbar global search memanggil endpoint metadata-only yang mencari key current aktif dengan limit 20. Contributor di-scope melalui `user_service_access`; Operator/Administrator dibatasi organization. Endpoint tidak memilih value, ciphertext, nonce, description, history, atau proposal, dan hasil selalu kembali ke halaman environment yang tetap memegang policy plaintext.

## Operasi

- `/health` hanya membuktikan process hidup; `/ready` menjalankan pemeriksaan database ringan tanpa data sensitif.
- Backup memakai `VACUUM INTO` dengan filename yang dibuat server dan directory allowlist `/backup`; regular-file/symlink checks, SQLite sanity, size, dan SHA-256 divalidasi sebelum audit sukses.
- Restore adalah offline; UI hanya membuat marker atomik `/data/restore-intent.json` setelah recent-auth. Marker mengikat identifier, size, dan SHA-256; startup membandingkan database aktif sebelum membuka SQLite, lalu menjalankan integrity/migration/key sanity, menulis durable `RESTORE_BACKUP`, dan baru menghapus marker.
- KEK rotation me-rewrap DEK yang sama dan me-encrypt ulang TOTP seed. DEK rotation me-encrypt ulang current, history, dan seluruh proposal terenkripsi dalam checkpoint batch; unsafe application writes diblokir sampai operation terminal. Detail ada di `key-rotation-design.md` dan `key-rotation-runbook.md`.
- Structured log memuat request ID, method, route template, status, duration, dan user ID bila ada; body dan query sensitif tidak dicatat.

## Deployment hardening

Container berjalan non-root, capabilities di-drop, `no-new-privileges`, root filesystem read-only, hanya `/data` dan `/backup` writable, dan `/run/secrets` read-only. Production wajib berada di balik HTTPS dan private/identity-aware access layer. SQLite dan backup mendapat owner/mode minimum; backup KEK disimpan terpisah dari backup database.

## Architectural acceptance criteria

Desain dianggap terjaga jika semua jalur plaintext melewati policy + recent-auth yang sesuai, semua writes penting atomik dengan audit, API tidak lebih permisif daripada SSR, state ConfigDeck tidak mengklaim deployment tanpa tindakan Operator, dan aplikasi tetap satu binary/satu SQLite tanpa dependency operasional baru.
