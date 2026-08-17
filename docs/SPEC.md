Buat sebuah aplikasi internal bernama **ConfigDeck**: lightweight environment configuration portal untuk tim engineering dan operations.

Tujuan aplikasi ini BUKAN menjadi secret manager kompleks seperti Vault, Infisical, atau Phase. Fokus utama adalah mengelola environment variables per service dan environment dengan workflow manual menuju deployment platform apa pun.

## 1. Konteks penggunaan

Saat ini workflow tim seperti ini:

Developer sering meminta ke DevOps:

* “Mas, env untuk service ini di staging sekarang apa saja?”
* “Env `PAYMENT_URL` sudah di-set belum?”
* “Tolong update `PAYMENT_URL` di staging dengan value ini.”
* “Production sekarang pakai value apa?”

Tim operations adalah pihak yang memiliki akses ke deployment platform tujuan dan melakukan update environment variable secara manual melalui UI platform tersebut.

Aplikasi ini harus menjadi centralized environment configuration registry dan request portal.

Flow utama:

```text
Developer
    ↓
ConfigDeck
    ↓
lihat daftar env
buat request add/update/delete
    ↓
DevOps review
    ↓
DevOps copy KEY=VALUE
    ↓
paste ke deployment platform
    ↓
mark request as Applied
```

Tidak perlu integrasi API dengan deployment platform pada versi awal.

Deployment platform yang dipilih organisasi tetap menjadi runtime target.

ConfigDeck menjadi tempat developer mengetahui current known configuration dan status perubahan.

---

# 2. Tech Stack

Gunakan stack berikut.

Backend:

* Rust stable
* Axum
* Tokio
* SQLx dengan SQLite
* Serde
* Tower / Tower HTTP
* Argon2id untuk password hashing
* ChaCha20-Poly1305 sebagai default authenticated encryption; AES-256-GCM boleh jika ada alasan implementasi yang lebih kuat
* tracing + tracing-subscriber untuk logging
* thiserror / anyhow sesuai kebutuhan

Frontend:

Prioritaskan solusi ringan.

Pilihan utama:

* Server-side rendered HTML menggunakan Askama
* HTMX untuk interaksi dinamis
* HTMX harus di-host sebagai static asset lokal, bukan CDN
* Vanilla JavaScript hanya untuk browser API yang memang diperlukan seperti Clipboard API
* CSS sederhana atau Tailwind CSS

Jangan gunakan React, Vue, Next.js, Leptos, atau SPA framework pada MVP.

Aplikasi harus bisa berjalan nyaman dengan resource kecil. Target engineering (bukan klaim pasti sebelum benchmark):

```text
0.25–0.5 vCPU penggunaan normal
64–128 MB RAM idle/normal sebagai target
256 MB RAM limit yang nyaman
```

Target production adalah satu Rust binary, satu container, satu SQLite file, satu persistent data volume, dan satu persistent backup volume terpisah, tanpa Node runtime.

---

# 3. Deployment

Aplikasi harus mudah dijalankan melalui Docker Compose.

Hanya satu service utama:

```text
configdeck
```

Persistent data:

```text
/data/configdeck.db
```

Persistent backup volume terpisah:

```text
/backup
```

`/backup` harus dipasang sebagai writable volume terpisah dari `/data`. Tujuannya agar kehilangan/corruption pada volume data utama tidak sekaligus menghilangkan seluruh backup lokal. Backup off-host tetap direkomendasikan; volume `/backup` bukan pengganti off-host backup.

Master key dipasang sebagai secret file:

```text
/run/secrets/configdeck_master_key
```

Untuk KEK/master-key rotation, dukung secret file sementara kedua:

```text
/run/secrets/configdeck_master_key_previous
```

File `configdeck_master_key_previous` hanya boleh diperlukan selama proses rotasi KEK. Setelah seluruh active DEK berhasil di-re-wrap dan tervalidasi dengan KEK baru, file tersebut harus dihapus dari deployment. Jangan simpan KEK lama di SQLite atau registry key internal.

Prefer membaca master key dari file. Environment variable hanya boleh menjadi fallback development.

Sediakan:

* Dockerfile multi-stage
* docker-compose.yml
* `.env.example`
* healthcheck
* command khusus migration
* container berjalan sebagai non-root
* `no-new-privileges`
* drop Linux capabilities yang tidak diperlukan
* root filesystem read-only jika feasible
* hanya `/data` dan `/backup` yang writable; `/run/secrets` read-only

Target deployment adalah VPS / self-hosted environment.

Jangan membuat dependency terhadap Kubernetes.

---

# 4. Konsep data

Hierarki utama:

```text
Organization
└── Service
    └── Environment
        └── Variables
```

Untuk versi awal, Organization boleh hanya satu.

Contoh:

```text
payment-api
├── development
├── staging
└── production

auth-service
├── development
├── staging
└── production
```

Setiap environment variable memiliki:

```text
key
value
visibility
value_type
description
status
created_at
updated_at
created_by
updated_by
last_applied_at
last_applied_by
```

---

# 5. User roles

Jangan gunakan jabatan organisasi seperti `Developer` atau `DevOps` sebagai nama role. Gunakan capability-based roles.

Minimal ada tiga role:

## Contributor

Contributor dapat:

* login
* melihat service yang diberikan kepadanya
* melihat environment
* melihat daftar variable
* melihat key semua variable
* melihat value variable non-secret
* melihat `********` untuk secret
* melihat status variable
* melihat kapan terakhir applied
* membuat request:

  * add variable
  * update variable
  * delete variable
* melihat status request miliknya
* melihat history request

Contributor TIDAK boleh:

* melihat secret value
* meng-export secret
* mark request sebagai applied
* bypass approval
* mengubah production secara langsung

## Operator

Operator dapat:

* melihat seluruh service/environment
* melihat seluruh value termasuk secret
* reveal secret
* copy individual `KEY=VALUE`
* copy seluruh environment sebagai `.env`
* review request
* approve/reject
* mark applied
* edit variable secara langsung
* melihat audit log

## Administrator

Administrator memiliki seluruh kemampuan Operator ditambah:

* manage user
* manage role dan service access
* manage service/environment metadata
* manage system/security settings yang tersedia melalui UI
* membuat backup
* membuat restore intent dan menjalankan prosedur restore offline sesuai runbook
* menjalankan KEK rotation
* menjalankan DEK rotation
* melihat audit log administratif

Role harus merepresentasikan capability, bukan job title.

---

# 6. Security model

Ini sangat penting.

Secret tidak boleh hanya disembunyikan di frontend.

Contoh yang SALAH:

```json
{
  "key": "DATABASE_URL",
  "value": "postgres://secret"
}
```

lalu frontend menampilkan `******`.

Developer tidak boleh pernah menerima plaintext secret dari backend.

Untuk developer backend harus mengembalikan:

```json
{
  "key": "DATABASE_URL",
  "value": null,
  "visibility": "restricted"
}
```

atau hanya mengirim representasi masked.

Plaintext secret hanya boleh didecrypt setelah backend melakukan authorization dan memastikan user memiliki role yang sesuai.

---

# 7. Encryption

ENCRYPT SEMUA environment values at rest tanpa pengecualian.

`visibility` adalah satu-satunya source of truth untuk authorization terhadap plaintext value. Jangan membuat field `is_secret`, baik di database, domain model, maupun API. `visibility=restricted` berarti Contributor tidak boleh menerima plaintext; `visibility=public` berarti Contributor dengan service access boleh menerima plaintext setelah authorization backend.

Gunakan authenticated encryption dengan default:

```text
ChaCha20-Poly1305
```

Setiap encryption wajib menggunakan nonce unik/random yang benar. Jangan reuse nonce dengan key yang sama.

Gunakan envelope encryption:

```text
Master Key / KEK
      │
      └── wrap Data Encryption Key / DEK
                         │
                         └── encrypt environment values
```

Prefer satu DEK per environment agar sederhana tetapi blast radius lebih kecil.

Simpan key metadata dalam tabel `environment_keys`, bukan langsung sebagai kolom di `environments`. Database boleh menyimpan:

```text
environment_id
dek_version
wrapped_dek
wrapped_dek_nonce
kek_version
status
value_ciphertext
value_nonce
```

Master key/KEK TIDAK boleh disimpan di SQLite.

Gunakan stable metadata sebagai AAD, misalnya `service_id`, `environment_id`, `variable_id`, dan `version` agar ciphertext tidak dapat dipindahkan antar record tanpa authentication failure.

Bedakan dua jenis rotasi secara eksplisit:

```text
KEK / master-key rotation
→ decrypt wrapped DEK dengan KEK lama
→ re-wrap DEK yang sama dengan KEK baru
→ TIDAK perlu decrypt/re-encrypt seluruh environment value

Mekanisme operasional KEK rotation untuk MVP:

1. mount KEK baru sebagai `/run/secrets/configdeck_master_key`
2. mount KEK lama sementara sebagai `/run/secrets/configdeck_master_key_previous`
3. Administrator menjalankan operasi rotasi dari UI maintenance/security
4. aplikasi memvalidasi bahwa KEK lama dapat membuka seluruh `wrapped_dek` aktif
5. aplikasi re-wrap setiap DEK dengan KEK baru dan menaikkan `kek_version`
6. lakukan verifikasi decrypt terhadap sample/seluruh key metadata yang relevan sebelum commit final
7. audit event `ROTATE_KEK` dibuat tanpa key material
8. setelah sukses, hapus secret file `configdeck_master_key_previous` dari deployment

Jika previous KEK tidak tersedia atau tidak valid, operasi rotasi harus gagal aman tanpa memodifikasi existing wrapped DEK.

DEK rotation
→ generate DEK baru untuk environment
→ decrypt seluruh current value DAN seluruh encrypted historical value di environment dengan DEK lama
→ encrypt ulang seluruh current value DAN seluruh historical value dengan DEK baru
→ wrap DEK baru dengan KEK aktif
→ update `dek_version` pada seluruh record yang dienkripsi ulang
→ setelah seluruh transaksi sukses dan tervalidasi, hapus key material DEK lama sehingga tidak dapat dipakai lagi untuk decrypt data historis
```

Rotasi DEK wajib dilakukan jika DEK diduga bocor/compromised. Jangan mempertahankan wrapped DEK lama hanya demi membaca history, karena itu akan mempertahankan blast radius compromise. History harus ikut di-re-encrypt. Jangan menyatakan bahwa semua jenis rotasi dapat dilakukan hanya dengan re-wrap.

Jangan pernah log:

* secret plaintext
* master encryption key
* password
* session token

---

# 8. Authentication

Implementasikan local authentication terlebih dahulu.

User memiliki:

```text
email
password_hash
role
active
```

Password hashing:

```text
Argon2id
```

Session:

* server-side session
* HttpOnly
* Secure
* SameSite=Strict; Lax hanya jika ada alasan kompatibilitas yang didokumentasikan
* session expiration
* logout

Session ID harus cryptographically random. Jangan simpan raw session token di database; simpan hash seperti SHA-256.

Implementasikan idle timeout, absolute timeout, logout invalidation, dan session rotation setelah perubahan password/privilege jika relevan.

Operator dan Administrator WAJIB menggunakan TOTP 2FA saat login. Contributor juga harus mendukung TOTP dan boleh dibuat mandatory melalui setting organisasi; default production recommendation adalah mandatory untuk semua account.

Operasi sensitif seperti Reveal Secret, Copy Secret, `Preview .env`, `Copy .env`, melihat previous secret version, KEK rotation, DEK rotation, membuat backup, dan memulai prosedur restore harus membutuhkan recent authentication. Gunakan short privileged-auth window sekitar 5–10 menit; setelah habis, minta password + TOTP kembali.

Untuk operasi berdampak besar seperti `ROTATE_KEK`, `ROTATE_DEK`, dan restore, gunakan privileged-auth window yang sama atau lebih ketat daripada reveal/export biasa. Authorization backend tetap wajib; recent authentication bukan pengganti role/capability check.

Jangan menggunakan JWT jika tidak diperlukan.

Untuk aplikasi internal sederhana, prefer session-based authentication.

---

# 9. Authorization

Authorization harus dilakukan di backend.

Developer dapat diberikan access per service.

Contoh:

```text
developer-a

payment-api:
  development: read/request
  staging: read/request
  production: read/request
```

Untuk MVP cukup permission per service:

```text
user_service_access
```

Semua environment di service mengikuti access tersebut.

Namun desain schema agar nanti dapat diperluas menjadi permission per environment.

---

# 10. Variable types dan visibility

Pisahkan `value_type` dari `visibility`. Semua environment variable pada akhirnya tetap diexport sebagai string `KEY=VALUE`; type hanya dipakai untuk UX dan validation.

Minimal `value_type`:

```text
string
boolean
integer
url
multiline
```

Editor UI:

* `boolean` → toggle `true / false`
* `integer` → numeric input
* `url` → URL input + validation
* `string` → text input
* `multiline` → textarea

Tambahkan `visibility` minimal:

```text
public
restricted
```

`public` berarti Contributor dengan service access boleh melihat value.

`restricted` berarti Contributor hanya melihat `********`, sedangkan Operator/Administrator dapat reveal setelah authorization + recent auth.

Contoh kategori:

## Public config

Contoh:

```text
LOG_LEVEL=info
API_URL=https://api.example.com
PORT=8080
FEATURE_PAYMENT_V2=true
```

Contributor boleh melihat value.

## Secret

Contoh:

```text
DATABASE_URL
JWT_SECRET
SMTP_PASSWORD
API_SECRET_KEY
```

Contributor hanya melihat:

```text
DATABASE_URL=********
```

Operator/Administrator dapat melihat plaintext setelah authorization yang sesuai.

---

# 11. Environment list UI

Halaman environment harus seperti:

```text
payment-api / staging

KEY                  VALUE                        STATUS
------------------------------------------------------------
API_URL              https://staging.api...       Applied
LOG_LEVEL            info                         Applied
DATABASE_URL         ********                     Applied
JWT_SECRET           ********                     Pending Update
PAYMENT_SECRET       ********                     Not Applied
```

Tambahkan:

```text
Last Applied
Updated By
```

jika tidak membuat UI terlalu penuh.

Harus ada search/filter berdasarkan key.

---

# 12. Preview dan Copy `.env`

Ini salah satu fitur TERPENTING.

Operator harus memiliki primary action:

```text
Preview .env
```

Setelah recent-auth berhasil, tampilkan resolved environment final dan tombol:

```text
Copy .env
```

`Preview .env` lebih tepat daripada langsung `Copy All` karena Operator harus dapat memastikan hasil akhir sudah lengkap dan benar sebelum clipboard diisi. `Download .env` boleh menjadi fitur sekunder.

Output:

```env
API_URL=https://staging.api.example.com
LOG_LEVEL=info
DATABASE_URL=postgresql://username:password@host/db
JWT_SECRET=xxxxx
PAYMENT_SECRET=xxxxx
```

Format harus bisa langsung:

```text
Ctrl+C
↓
Deployment Platform Environment UI
↓
Ctrl+V
```

tanpa edit manual.

Perhatikan escaping value `.env`.

Gunakan format yang kompatibel dengan dotenv sebisa mungkin.

Jika value memiliki:

* newline
* quote
* whitespace
* `#`
* karakter khusus

pastikan hasil export tidak rusak.

Tambahkan pilihan sekunder:

```text
Copy Selected
Download .env
```

Namun `Preview .env` → `Copy .env` adalah workflow utama.

Contributor tidak boleh mengakses resolved `.env` yang mengandung restricted value.

---

# 13. Individual copy

Untuk DevOps, setiap row memiliki:

```text
Copy KEY=VALUE
```

contoh:

```text
PAYMENT_URL=https://payment.example.com
```

Untuk developer:

* public config boleh copy
* secret hanya:

```text
PAYMENT_SECRET=********
```

atau disable copy.

---

# 14. Change request dan value fulfillment

Contributor tidak langsung mengubah current value. Contributor membuat satu change set yang dapat berisi satu atau banyak perubahan agar request seperti penambahan credential database dapat dikerjakan sebagai satu unit.

Untuk setiap requested variable, Contributor memilih salah satu:

```text
I know the value
Operator will provide the value
```

Jika Contributor mengetahui restricted value, ia boleh memasukkannya sekali. Setelah submit nilainya langsung dienkripsi dan Contributor tidak boleh reveal kembali.

Jika Contributor tidak mengetahui credential seperti database username/password, ia cukup menentukan key, type, visibility, description/reason, lalu memilih `Operator will provide the value`. Operator kemudian mengisi value dari UI tanpa perlu request baru.

Jenis request:

```text
ADD
UPDATE
DELETE
```

Data request:

```text
id
service_id
environment_id
variable_id nullable
action
key
encrypted_proposed_value
value_source
value_fulfilled_by nullable
value_fulfilled_at nullable
proposed_visibility
proposed_value_type
description
reason
status
requested_by
requested_at
reviewed_by
reviewed_at
applied_by
applied_at
rejection_reason
```

`value_source` harus berupa enum yang eksplisit:

```text
REQUESTER_PROVIDED
OPERATOR_PROVIDED
```

`REQUESTER_PROVIDED` berarti Contributor mengirim value saat membuat request. `OPERATOR_PROVIDED` berarti request dibuat tanpa value dan harus dipenuhi Operator sebelum change set dapat menjadi `READY_TO_APPLY`.

---

# 15. Status workflow

Status harus menggambarkan kesiapan config.

```text
REQUESTED
NEEDS_INPUT
READY_TO_APPLY
APPLIED
REJECTED
```

Flow:

```text
Contributor submit
      ↓
REQUESTED
      ↓
Jika ada key tanpa value
      ↓
NEEDS_INPUT
      ↓
Operator isi semua missing value
      ↓
READY_TO_APPLY
      ↓
Preview .env → Copy .env → paste ke deployment platform
      ↓
Mark Applied
      ↓
APPLIED
```

Operator juga boleh:

```text
REQUESTED / NEEDS_INPUT / READY_TO_APPLY → REJECTED
```

Sebuah change set hanya boleh menjadi `READY_TO_APPLY` jika semua ADD/UPDATE yang membutuhkan value sudah memiliki resolved value. Dengan demikian `Preview .env` selalu menghasilkan config final tanpa placeholder.

---

# 16. Important state semantics

Jangan mengatakan bahwa config sudah diterapkan ke deployment platform hanya karena perubahan sudah disimpan di ConfigDeck.

Bedakan:

```text
Saved in ConfigDeck
```

dengan:

```text
Applied to deployment platform
```

`APPLIED` hanya boleh terjadi ketika DevOps secara eksplisit menekan:

```text
Mark as Applied
```

karena deployment masih manual.

---

# 17. Applying a request

Saat DevOps membuka request:

```text
UPDATE JWT_SECRET
payment-api / staging

Current:
xxxxxxxx

Requested:
yyyyyyyy

Reason:
Credential rotation

Requested by:
developer@example.com
```

DevOps dapat:

```text
Reject
Approve
Copy KEY=VALUE
Mark Applied
```

Untuk secret, current dan requested value hanya boleh ditampilkan kepada DevOps.

---

# 18. Batch pending changes

Buat halaman:

```text
Pending Changes
```

Contoh:

```text
payment-api / staging

PAYMENT_URL       UPDATE
JWT_SECRET        UPDATE
NEW_FEATURE       ADD
```

DevOps harus bisa:

```text
Copy pending configuration as .env
```

atau:

```text
Copy full resulting environment
```

Prefer opsi kedua.

Artinya jika current environment:

```env
A=1
B=2
C=3
```

dan pending:

```text
B=20
D=4
```

DevOps dapat preview resulting environment:

```env
A=1
B=20
C=3
D=4
```

dan copy semuanya sekaligus ke deployment platform.

Ini akan sangat membantu workflow manual.

---

# 19. Mark batch as applied

Setelah Operator paste ke deployment platform:

```text
Mark all selected changes as Applied
```

Kemudian:

* current variable state diperbarui
* request berubah menjadi `APPLIED`
* `applied_at` terisi
* `applied_by` terisi
* audit log dibuat

Gunakan transaction database agar proses atomik.

---

# 20. History

Setiap variable memiliki history.

Contoh:

```text
PAYMENT_URL

v4
13 Aug 2026
updated by developer-a
applied by devops-a

v3
2 Aug 2026
updated by devops-a

v2
15 Jul 2026
...
```

Untuk secret, history value tetap encrypted.

Developer dapat melihat metadata perubahan tetapi tidak secret plaintext.

DevOps boleh melihat previous value jika diperlukan.

---

# 21. Audit log

Audit event minimal:

```text
LOGIN
LOGOUT

VIEW_SECRET
COPY_SECRET
EXPORT_ENV

CREATE_VARIABLE
UPDATE_VARIABLE
DELETE_VARIABLE

CREATE_REQUEST
APPROVE_REQUEST
REJECT_REQUEST
APPLY_REQUEST

CREATE_SERVICE
DELETE_SERVICE

CREATE_USER
UPDATE_USER_ACCESS

ROTATE_KEK
ROTATE_DEK
CREATE_BACKUP
CREATE_RESTORE_INTENT
RESTORE_BACKUP
```

Audit record:

```text
timestamp
user
action
service
environment
variable_key
request_id
ip_address
user_agent
metadata
```

Jangan menyimpan secret plaintext pada metadata audit.

---

# 22. Dashboard

Developer dashboard:

```text
My Services

payment-api
  staging       14 variables
                1 pending change

auth-service
  staging       9 variables
                up to date
```

DevOps dashboard:

```text
Pending Changes: 4
Services: 12
Environments: 30

Recent Activity
```

Tidak perlu dashboard kompleks atau chart.

Prioritaskan kecepatan dan usability.

---

# 23. Service page

Struktur:

```text
payment-api

[development] [staging] [production]
```

Setiap tab environment menampilkan variables.

Developer harus bisa cepat berpindah environment untuk membandingkan key.

Tambahkan optional feature:

```text
Compare staging ↔ production
```

Tidak perlu membandingkan secret plaintext.

Contoh:

```text
KEY                  STAGING        PRODUCTION
------------------------------------------------
API_URL              configured     configured
DATABASE_URL         configured     configured
PAYMENT_SECRET       configured     missing
FEATURE_X            true           false
```

Ini optional, lakukan setelah MVP selesai.

---

# 24. Database schema

Buat migration SQL yang baik.

Minimal tables:

```text
users
services
environments
environment_keys
user_service_access
variables
variable_versions
change_requests
audit_logs
sessions
```

Pertimbangkan unique constraint:

```text
(service_id, environment_id, key)
```

atau lebih tepat:

```text
(environment_id, key)
```

Environment harus terkait dengan service.

---

# 25. Suggested schema

Contoh konsep:

```sql
users
- id UUID
- email TEXT UNIQUE
- password_hash TEXT
- role ENUM
- active BOOLEAN
- created_at TIMESTAMPTZ

services
- id UUID
- name TEXT UNIQUE
- description TEXT
- created_at TIMESTAMPTZ

environments
- id UUID
- service_id UUID
- name TEXT
- created_at TIMESTAMPTZ
- UNIQUE(service_id, name)

environment_keys
- id UUID
- environment_id UUID NOT NULL
- dek_version BIGINT NOT NULL
- wrapped_dek BLOB nullable
- wrapped_dek_nonce BLOB nullable
- kek_version BIGINT NOT NULL
- status TEXT NOT NULL CHECK (status IN ('active','retired'))
- created_at TIMESTAMPTZ NOT NULL
- retired_at TIMESTAMPTZ nullable
- UNIQUE(environment_id, dek_version)

Hanya row `active` yang boleh memiliki key material usable. Setelah DEK rotation selesai dan seluruh current + historical value sudah di-re-encrypt, row lama boleh dipertahankan sebagai metadata audit tetapi `wrapped_dek` dan `wrapped_dek_nonce` harus dihapus/null-kan agar DEK lama tidak dapat dipulihkan dari database.

variables
- id UUID
- environment_id UUID
- key TEXT
- encrypted_value BLOB NOT NULL
- value_nonce BLOB NOT NULL
- dek_version BIGINT NOT NULL
- visibility TEXT NOT NULL CHECK (visibility IN ('public','restricted'))
- value_type TEXT NOT NULL CHECK (value_type IN ('string','boolean','integer','url','multiline'))
- description TEXT
- version BIGINT
- updated_by UUID
- updated_at TIMESTAMPTZ
- last_applied_by UUID nullable
- last_applied_at TIMESTAMPTZ nullable
- UNIQUE(environment_id, key)

variable_versions
- id UUID
- variable_id UUID NOT NULL
- environment_id UUID NOT NULL
- version BIGINT NOT NULL
- encrypted_value BLOB NOT NULL
- value_nonce BLOB NOT NULL
- dek_version BIGINT NOT NULL
- visibility TEXT NOT NULL CHECK (visibility IN ('public','restricted'))
- value_type TEXT NOT NULL CHECK (value_type IN ('string','boolean','integer','url','multiline'))
- changed_by UUID NOT NULL
- changed_at TIMESTAMPTZ NOT NULL
- change_request_id UUID nullable
- UNIQUE(variable_id, version)

change_requests
- id UUID
- environment_id UUID
- variable_id UUID nullable
- action ENUM
- key TEXT
- encrypted_proposed_value BLOB nullable
- proposed_value_nonce BLOB nullable
- proposed_dek_version BIGINT nullable
- proposed_visibility TEXT NOT NULL CHECK (proposed_visibility IN ('public','restricted'))
- proposed_value_type TEXT NOT NULL CHECK (proposed_value_type IN ('string','boolean','integer','url','multiline'))
- value_source TEXT NOT NULL CHECK (value_source IN ('REQUESTER_PROVIDED','OPERATOR_PROVIDED'))
- value_fulfilled_by UUID nullable
- value_fulfilled_at TIMESTAMPTZ nullable
- reason TEXT
- status ENUM
- requested_by UUID
- requested_at TIMESTAMPTZ
- reviewed_by UUID nullable
- reviewed_at TIMESTAMPTZ nullable
- applied_by UUID nullable
- applied_at TIMESTAMPTZ nullable
- rejection_reason TEXT nullable
```

Semua environment value WAJIB dienkripsi. Schema tidak boleh memiliki `plaintext_value`, `plaintext_proposed_value`, atau kolom plaintext ekuivalen. Public/restricted hanya memengaruhi authorization setelah decrypt, bukan mekanisme storage.

`environment_keys` adalah source of truth untuk DEK per environment. `dek_version` pada `variables`, `variable_versions`, dan proposed encrypted values harus menunjuk versi DEK yang digunakan untuk ciphertext tersebut. Implementasi harus menjamin maksimal satu key berstatus `active` per environment.

---

# 26. Recommended encryption model

Prefer:

```text
all environment values encrypted at rest
```

Database:

```text
encrypted_value
nonce
dek_version
```

Tidak perlu plaintext column.

`visibility` adalah satu-satunya field yang menentukan apakah Contributor boleh menerima hasil decrypt. Jangan tambahkan derived/persisted field `is_secret`.

Backend:

```text
DevOps → decrypt → return value

Contributor + visibility:public
       → decrypt → return value

Contributor + visibility:restricted
       → DON'T decrypt
       → return masked state
```

Ini adalah desain yang disukai.

---

# 27. Master key validation

Saat application startup:

* validasi encryption key tersedia
* validasi panjang key
* fail-fast jika key invalid

Jangan membuat default encryption key.

Jangan generate random key saat boot karena data akan tidak bisa didecrypt setelah restart.

---

# 28. Backup, Restore, dan Master Key

Master key wajib:

* tersedia saat startup
* tidak memiliki default production value
* tidak auto-generate saat boot production
* fail-fast jika hilang/invalid
* tidak pernah di-log
* tidak disimpan di SQLite
* prefer dibaca dari `/run/secrets/configdeck_master_key`

Jangan melakukan backup SQLite dengan raw `cp` saat aplikasi aktif. Karena stack utama memakai SQLx dan tidak perlu dependency tambahan hanya untuk backup, gunakan SQLite `VACUUM INTO` sebagai strategi backup utama untuk menghasilkan snapshot konsisten.

Backup harus tersedia dari UI Administrator atau mekanisme operasional internal aplikasi, bukan custom CLI sebagai requirement MVP.

Contoh operasi internal dengan format filename yang konsisten dan aman terhadap collision:

```sql
VACUUM INTO '/backup/configdeck-YYYYMMDDTHHMMSSZ.db';
```

Validasi destination path agar user tidak dapat menulis ke lokasi arbitrary. Jangan memasukkan raw path dari browser langsung ke statement SQL tanpa validation/allowlist.

Backup database dan backup master key harus disimpan terpisah secara aman. Dokumentasikan dan test restore. Backup belum dianggap valid sampai pernah diuji restore.

## Restore strategy untuk MVP

JANGAN implementasikan live restore terhadap SQLite yang sedang dibuka oleh application connection pool. Untuk MVP gunakan **offline restore** karena lebih sederhana, lebih dapat diprediksi, dan sesuai dengan single-container/single-operator architecture.

Runbook restore minimum:

```text
1. Administrator melakukan recent-auth dan membuat restore intent dari UI
2. ConfigDeck mencatat metadata restore intent tanpa secret plaintext
3. stop container ConfigDeck
4. backup current `/data/configdeck.db` sebagai safety copy
5. validasi file backup yang akan direstore
6. ganti `/data/configdeck.db` dengan snapshot backup secara atomik
7. pastikan owner/permission file benar
8. pastikan `/run/secrets/configdeck_master_key` yang sesuai tersedia
9. start container ConfigDeck
10. startup melakukan integrity check + migration compatibility check + key/decrypt sanity check
11. setelah startup sukses, ConfigDeck menulis `RESTORE_BACKUP` sebagai audit event pertama yang merepresentasikan restore tersebut
```

Karena database sumber audit ikut diganti saat offline restore, `RESTORE_BACKUP` tidak boleh diasumsikan sudah tercatat sebelum file database diganti. Untuk MVP, gunakan mekanisme **restore intent marker** di luar SQLite, misalnya file metadata kecil pada path operasional yang terkontrol seperti:

```text
/data/restore-intent.json
```

File marker hanya boleh berisi metadata non-secret seperti:

```text
requested_by_user_id
requested_at
backup_identifier
reason
```

Untuk MVP, `backup_identifier` harus berupa identifier yang tidak ambigu dan berasal dari filename backup yang tervalidasi pada volume `/backup`, misalnya:

```text
configdeck-20260813T142500Z.db
```

Jangan izinkan arbitrary filesystem path sebagai `backup_identifier`. Resolve identifier hanya terhadap allowlisted backup directory `/backup`.

Jangan simpan password, TOTP, KEK, DEK, plaintext environment value, atau raw session token di marker tersebut.

Saat startup setelah restore, jika marker valid ditemukan dan database berhasil dibuka serta diverifikasi, aplikasi harus:

```text
write RESTORE_BACKUP audit event
→ include restore metadata yang aman
→ fsync/commit audit
→ hapus restore-intent marker
```

Jika startup/validation gagal, jangan hapus marker sehingga operator masih memiliki bukti bahwa restore belum selesai. Dokumentasikan recovery path di runbook.

Restore dari UI berarti UI hanya membuat **restore intent** dan menampilkan runbook/confirmation; penggantian file database tetap dilakukan saat container offline. Jangan membuat endpoint HTTP yang mengganti live SQLite database file pada MVP.

---

# 29. CSRF dan web security

Karena menggunakan session auth:

Implementasikan:

* CSRF protection
* secure cookies
* XSS escaping
* Content-Security-Policy
* X-Content-Type-Options
* Referrer-Policy
* frame protection
* rate limit login per IP / trusted client identity
* exponential backoff per account setelah repeated failures
* jangan gunakan hard account lockout otomatis berbasis jumlah kegagalan saja karena dapat dipakai sebagai vektor denial-of-service terhadap account lain
* no-store cache policy untuk response yang mengandung plaintext secret
* trusted proxy configuration agar `X-Forwarded-For` tidak mudah dipalsukan

Gunakan security headers melalui Tower middleware jika memungkinkan.

Target CSP:

```text
default-src 'self';
script-src 'self';
style-src 'self';
img-src 'self' data:;
connect-src 'self';
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
```

Hindari `'unsafe-inline'` untuk script.

---

# 30. Secret reveal UX

DevOps UI secara default tetap tampil:

```text
DATABASE_URL=********
```

Untuk melihat:

```text
Reveal
```

Kemudian value tampil sementara.

Jangan otomatis menampilkan semua plaintext secret pada halaman normal.

Flow reveal wajib:

```text
POST reveal
→ verify session
→ verify recent auth
→ verify backend authorization
→ audit VIEW_SECRET
→ decrypt
→ return small HTML fragment
```

Secret plaintext tidak boleh disimpan ke localStorage, sessionStorage, IndexedDB, atau global JavaScript state.

Tetapi bulk export:

```text
Copy All as .env
```

boleh melakukan decrypt seluruh environment setelah confirmation.

Log event:

```text
EXPORT_ENV
```

Response reveal/export wajib menggunakan:

```text
Cache-Control: no-store
Pragma: no-cache
```

Tidak perlu confirmation modal yang berlebihan.

---

# 31. Secret request UX

Developer boleh memasukkan proposed secret baru.

Contoh:

```text
JWT_SECRET
New value: [***************]
Visibility: restricted
Reason: rotation
```

Developer harus dapat memasukkan value tetapi setelah submit tidak boleh bisa melihatnya kembali.

Server encrypt segera.

Sesudah request disimpan:

```text
JWT_SECRET
Proposed value: ********
```

DevOps dapat melihat plaintext.

Ini penting.

---

# 32. Request without value dan credential fulfillment

Contributor juga boleh request:

```text
Please set DATABASE_URL
```

tanpa mengetahui value.

Tambahkan opsi:

```text
Operator will provide the value
```

Contoh:

```text
ADD DATABASE_URL

value: null
reason:
New database for payment service
```

Kemudian Operator mengisi value sebelum apply. Selama masih ada required key tanpa value, change set berstatus `NEEDS_INPUT` dan `Preview .env` / `Copy .env` untuk resulting configuration harus disabled.

Contoh credential request ideal:

```text
DB_HOST      type:string   visibility:restricted   Operator will provide
DB_PORT      type:integer  visibility:public       value:5432
DB_NAME      type:string   visibility:restricted   Operator will provide
DB_USER      type:string   visibility:restricted   Operator will provide
DB_PASSWORD  type:string   visibility:restricted   Operator will provide
```

Operator mengisi seluruh missing value, lalu status otomatis berubah `NEEDS_INPUT → READY_TO_APPLY`.

Pada tahap `READY_TO_APPLY`, `Preview .env` harus menampilkan hasil gabungan current configuration + ADD/UPDATE/DELETE dari change set. Tidak boleh ada `***`, `<missing>`, null, atau placeholder dalam resolved `.env`.

---

# 33. Import existing deployment environment

Buat fitur DevOps:

```text
Import .env
```

DevOps dapat paste:

```env
API_URL=https://...
DATABASE_URL=postgres://...
REDIS_URL=redis://...
```

Parser membaca semua variable.

Tampilkan preview:

```text
API_URL          public/secret?
DATABASE_URL     public/secret?
REDIS_URL        public/secret?
```

Default:

```text
default visibility = restricted
```

agar aman. Gunakan istilah `visibility=restricted` secara konsisten; jangan gunakan kembali istilah `secret` sebagai nama field internal.

DevOps kemudian dapat menandai variable tertentu sebagai public config.

Ini penting untuk initial migration dari deployment platform yang sudah digunakan.

---

# 34. Preview/Copy existing environment

Operator:

```text
Preview .env
```

dan:

```text
Copy .env
```

Harus menjadi fitur first-class.

Jangan membuat user harus klik satu-satu variable.

---

# 35. UI philosophy

UI harus:

* sederhana
* cepat
* desktop-first tetapi responsive
* tidak terlalu banyak modal
* tidak penuh animasi
* keyboard-friendly
* cocok untuk internal engineering tool

Inspirasi UX:

```text
GitHub settings
Self-hosted deployment consoles
Infisical
Phase
```

tetapi jangan menyalin branding.

Gunakan table sebagai interface utama.

---

# 36. Resource efficiency

Karena alasan utama memilih Rust adalah resource efficiency:

* hindari dependency berat jika tidak perlu
* gunakan SQLite connection/pool configuration yang konservatif dan sesuai pola concurrency aplikasi internal
* static assets minimal
* tidak perlu Redis untuk MVP
* tidak perlu message queue
* tidak perlu Elasticsearch
* tidak perlu Node server runtime
* tidak perlu microservices

Arsitektur harus berupa:

```text
single Rust application
+
SQLite embedded database
```

Monolith modular.

---

# 37. Project structure

Gunakan struktur clean tetapi jangan over-engineer.

Contoh:

```text
src/
├── main.rs
├── config.rs
├── db.rs
├── error.rs
├── auth/
├── crypto/
├── users/
├── services/
├── environments/
├── variables/
├── requests/
├── audit/
├── web/
└── templates/
```

Pisahkan:

```text
routes
handlers
services/business logic
repositories/database
```

jika memang membantu.

Jangan menerapkan DDD kompleks.

---

# 38. API

Meskipun UI server-rendered, sediakan internal REST API yang bersih untuk kemungkinan automation di masa depan.

Contoh:

```text
GET    /api/services
GET    /api/services/:id/environments
GET    /api/environments/:id/variables

POST   /api/change-requests

POST   /api/change-requests/:id/approve
POST   /api/change-requests/:id/reject
POST   /api/change-requests/:id/apply

GET    /api/environments/:id/export
```

API authorization harus sama ketatnya dengan UI.

Untuk MVP API tidak perlu access token eksternal.

Session auth boleh digunakan.

Namun desain agar nanti dapat menambahkan service account/token.

---

# 39. Health endpoints

Tambahkan:

```text
GET /health
GET /ready
```

`/health`:

application alive.

`/ready`:

cek database.

Jangan expose secret/config melalui endpoint ini.

---

# 40. Observability

Gunakan structured logging.

Contoh:

```text
request_id
method
path
status
duration
user_id
```

Jangan log:

```text
request body
```

secara default karena dapat mengandung secret.

Tambahkan request ID.

---

# 41. Error handling

Jangan expose internal database errors ke client.

User-facing:

```text
Unable to save configuration.
```

Server log:

```text
database error...
```

Tetapi pastikan server log tidak berisi secret.

---

# 42. Testing

Minimal test untuk:

## Crypto

* encrypt/decrypt
* wrong key fails
* modified ciphertext fails

## Authorization

* developer cannot read secret
* developer can read public config
* DevOps can read secret
* user cannot access unassigned service

## Requests

* developer creates request
* developer cannot apply
* DevOps can approve
* DevOps can mark applied

## Export

* DevOps receives full `.env`
* developer cannot export secret values

## Dotenv

Test escaping:

```text
spaces
quotes
#
newlines
=
unicode
empty value
```

---

# 43. Initial administrator

Saat pertama kali start, dukung bootstrap admin melalui environment:

```text
CONFIGDECK_ADMIN_EMAIL
CONFIGDECK_ADMIN_PASSWORD
```

Buat admin hanya jika database belum mempunyai user.

Jangan reset password pada setiap restart.

Setelah bootstrap berhasil, dokumentasikan agar password environment variable dihapus.

Jangan membuat custom CLI ConfigDeck sebagai requirement. Semua operasi normal harus dapat dilakukan melalui web UI dan startup/deployment flow yang sederhana.

---

# 44. First-run experience

Admin login dan menyelesaikan enrollment TOTP.

Sebelum masuk ke aplikasi utama, tampilkan authenticated organization setup:

* organization name wajib, dapat diinput Administrator;
* organization logo opsional berupa upload PNG/WebP maksimal 256 KiB;
* jangan render remote logo URL atau user-uploaded SVG pada MVP;
* logo ConfigDeck adalah SVG lokal yang dibundel bersama aplikasi;
* tagline produk adalah `Configuration Management Platform`.

Setelah setup organisasi selesai, Administrator dapat membuat account Contributor,
Operator, atau Administrator dari halaman `Users & Access`. Jangan menyediakan
default account selain bootstrap Administrator.

Buat:

```text
Service
payment-api
```

Environment otomatis:

```text
development
staging
production
```

Ketiga environment standar dibuat otomatis secara atomik saat service dibuat,
sehingga user tidak perlu membuatnya satu per satu. UI utama selalu
memprioritaskan urutan Development, Staging, Production. Environment custom
tetap tersedia sebagai opsi lanjutan untuk kebutuhan seperti QA, preview, atau
sandbox, tetapi bukan bagian dari alur normal.

Lalu:

```text
Import .env
```

paste current environment dari deployment platform.

Kemudian assign developer.

Selesai.

---

# 45. MVP priority

Kerjakan dalam urutan ini.

## Phase 1 — Foundation

* Rust Axum project
* SQLite/SQLx
* migration
* auth
* session
* role
* envelope encryption
* CSRF
* security headers
* TOTP

## Phase 2 — Core registry

* service
* environment
* variables
* masking
* import `.env`
* copy/export `.env`

## Phase 3 — Workflow

* developer access
* change request
* pending/approved/applied/rejected
* apply workflow

## Phase 4 — Operations

* audit log
* history
* user management
* access management
* backup/restore
* key rotation

## Phase 5 — polish

* search/filter
* batch action
* compare environments
* UX improvements

Jangan implementasikan advanced features sebelum core flow bekerja.

---

# 46. Explicit non-goals

JANGAN implementasikan dulu:

* Kubernetes integration
* deployment-platform API integration
* GitHub Actions integration
* dynamic secrets
* automatic rotation
* secret leasing
* PKI
* SSH certificate issuance
* cloud IAM integration
* HashiCorp Vault compatibility
* distributed architecture
* Redis
* Kafka
* background worker system
* WebSocket
* Terraform provider
* CLI secret injection
* SDK
* OIDC/SSO
* LDAP

Semua itu di luar MVP.

---

# 47. Future compatibility

Walaupun tidak dibuat sekarang, desain database/API jangan menghalangi kemungkinan:

```text
ConfigDeck
   ↓
Deployment Platform API
```

di masa depan.

Misalnya nanti setiap environment dapat memiliki:

```text
deployment_target
external_service_id
sync_mode
```

tetapi kolom ini belum perlu sekarang.

---

# 48. Definition of Done

MVP dianggap selesai jika flow berikut bekerja end-to-end:

### Scenario A — existing env

DevOps:

1. Login
2. Create `payment-api`
3. Open `staging`
4. Paste current `.env` dari deployment platform
5. Tandai `API_URL` sebagai public
6. Tandai `DATABASE_URL` dan `JWT_SECRET` sebagai secret
7. Assign developer

Developer login dan melihat:

```text
API_URL=https://...
DATABASE_URL=********
JWT_SECRET=********
```

### Scenario B — developer request

Developer:

1. Open `payment-api / staging`
2. Request:

```text
PAYMENT_URL=https://new-payment.example.com
```

3. Submit

Status:

```text
Pending
```

### Scenario C — DevOps apply

DevOps:

1. Open Pending Changes
2. Review request
3. Approve
4. Preview resulting `.env`
5. Click:

```text
Copy All as .env
```

hasil:

```env
API_URL=https://...
DATABASE_URL=...
JWT_SECRET=...
PAYMENT_URL=https://new-payment.example.com
```

6. Paste ke deployment platform
7. Klik:

```text
Mark Applied
```

Developer kemudian melihat:

```text
PAYMENT_URL=https://new-payment.example.com
Status: Applied
```

### Scenario D — secret request

Developer request:

```text
JWT_SECRET=<new secret>
```

Setelah submit developer hanya melihat:

```text
JWT_SECRET=********
Pending
```

DevOps dapat reveal requested value.

---

# 49. Delivery and verification strategy

## Known operational limitation — DEK rotation

Karena MVP tidak menggunakan background worker, rotasi DEK adalah operasi maintenance sinkron dan berpotensi berjalan lama pada environment dengan history besar. Implementasi harus meminimalkan lock time SQLite dan mendokumentasikan bahwa rotasi DEK sebaiknya dilakukan pada maintenance window untuk environment besar.

Jika jumlah current + historical encrypted records cukup besar, implementasikan pemrosesan dalam batch yang aman dan terverifikasi, tetapi jangan membuat state parsial yang ambigu. Desain batching harus memastikan setiap ciphertext tetap dapat ditelusuri ke `dek_version` yang benar sampai rotasi benar-benar selesai. Jangan menghapus wrapped DEK lama sebelum seluruh record berhasil dire-encrypt, tervalidasi, dan state rotasi dinyatakan selesai.

Known limitation ini harus dicantumkan di README/runbook. Background worker atau asynchronous rotation orchestration tetap di luar MVP.

Target akhir adalah project yang benar-benar runnable. Pengembangan dan verifikasi dilakukan bertahap sesuai Phase 1–5 pada section 45.

Sebelum coding, hasilkan dan finalkan terlebih dahulu:

1. architecture summary
2. database model final
3. threat model
4. envelope encryption design
5. pemisahan KEK rotation vs DEK rotation
6. session/TOTP/recent-auth design
7. authorization matrix
8. implementation plan per phase

Kemudian implementasikan satu phase pada satu waktu. Setiap phase harus build/test bersih sebelum lanjut ke phase berikutnya.

Target artifact akhir setelah seluruh phase selesai:

1. full source code
2. Cargo.toml
3. SQL migrations
4. templates
5. static assets
6. Dockerfile
7. docker-compose.yml
8. `.env.example`
9. README
10. commands untuk development
11. commands untuk production
12. automated tests
13. security notes
14. architecture notes
15. backup/restore runbook
16. KEK/DEK rotation runbook

README harus mencakup:

```bash
docker compose up -d
```

dan aplikasi harus dapat digunakan setelah setup awal. Jangan mengklaim phase atau final project selesai sebelum build/test yang relevan benar-benar dijalankan.

---

# 50. Engineering principles

Prioritaskan:

```text
security
simplicity
resource efficiency
maintainability
predictable behavior
```

di atas:

```text
abstraction
framework complexity
feature count
visual effects
```

Jika ada pilihan antara solusi sederhana dan sophisticated, pilih solusi sederhana selama security tidak dikorbankan.

Ini adalah INTERNAL DEVOPS TOOL, bukan SaaS multi-tenant.

Buat seperti tool yang realistis untuk dipelihara oleh satu DevOps engineer.

---

# 51. Implementation requirements

Sebelum coding:

1. buat architecture summary singkat
2. buat database model
3. buat threat model singkat yang mencakup stolen SQLite/backup, developer bypass UI, stolen DevOps session, XSS, CSRF, brute force, log leakage, browser cache leakage, tampered ciphertext, lost/compromised master key, container filesystem access, malicious `.env` import, dan reverse-proxy header spoofing
4. jelaskan envelope encryption dan key rotation design
5. jelaskan session/TOTP/recent-auth design
6. buat implementation plan

Setelah desain di atas konsisten dan tidak memiliki contradiction, implementasikan Phase 1 terlebih dahulu. Jangan lompat ke seluruh feature-set sekaligus. Setelah suatu phase lolos format, clippy, test, dan build yang relevan, baru lanjut ke phase berikutnya.

Detail kecil yang ambigu harus diselesaikan dengan default yang aman dan asumsi yang terdokumentasi.

Setelah implementasi:

1. jalankan formatter
2. jalankan clippy
3. jalankan test
4. build release
5. jalankan Docker build
6. perbaiki error sampai semua berhasil

Gunakan:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

Jika tooling tersedia, jalankan juga:

```bash
cargo audit
```

Jangan membuat build gagal hanya karena `cargo-audit` belum terpasang; dokumentasikan cara install.

Pastikan tidak ada secret test yang ikut masuk repository.

Sebelum menyimpan production credential, semua requirement berikut harus sudah terpenuhi:

```text
✓ HTTPS / reverse proxy
✓ private or identity-aware access layer
✓ encrypt all values
✓ envelope encryption
✓ master key terpisah dari database
✓ Argon2id
✓ server-side hashed sessions
✓ Secure/HttpOnly/SameSite cookie
✓ backend authorization
✓ CSRF
✓ CSP/security headers
✓ no plaintext secret logging
✓ no browser/proxy caching untuk secret response
✓ TOTP Operator/Administrator saat login
✓ recent authentication untuk reveal/export
✓ recent authentication untuk backup/restore dan KEK/DEK rotation
✓ audit privileged actions
✓ non-root container
✓ SQLite file permission hardening
✓ proper backup
✓ tested restore
✓ security tests pass
```

Final engineering rule:

```text
Simple architecture
Strong security boundary
Minimal attack surface
Server-side authorization
Encrypted by default
Auditable privileged actions
No plaintext unless explicitly needed
```

Jangan mencoba membuat mini Vault. Buat environment configuration portal yang kecil, aman, hemat resource, mudah dipelihara, dan sangat bagus untuk workflow manual tim engineering/operations menuju deployment platform apa pun.

Setiap release harus menyediakan ringkasan:

* architecture
* security decisions
* cara menjalankan
* default admin bootstrap
* known limitations
* roadmap yang masuk akal
