# Envelope Encryption and Key Rotation Design

Status: final design baseline. Default AEAD adalah ChaCha20-Poly1305.

## Key hierarchy dan format

- KEK adalah 32-byte random master key dari `/run/secrets/configdeck_master_key`; previous KEK hanya dari file sementara yang ditentukan spec.
- Satu random 32-byte DEK aktif per environment. Database menyimpan wrapped DEK, nonce, version, status, dan non-secret KEK fingerprint/version; tidak pernah KEK.
- Setiap encrypt memakai nonce 96-bit baru dari OS CSPRNG. Nonce uniqueness tidak bergantung pada counter database.
- Ciphertext menyimpan format/algorithm version secara eksplisit melalui kolom metadata yang tervalidasi; implementasi MVP hanya menerima suite yang didukung.
- Wrapped DEK menggunakan KEK langsung untuk AEAD dengan domain-separated AAD. TOTP seed menggunakan subkey purpose-specific yang diturunkan dari KEK dengan HKDF-SHA-256; environment values selalu menggunakan DEK.

File KEK menerima satu encoding canonical yang didokumentasikan (base64 standard untuk tepat 32 byte setelah decode). Whitespace luar boleh di-trim; panjang/encoding lain gagal. Aplikasi menghitung fingerprint non-secret `SHA-256("configdeck-kek-fingerprint-v1" || KEK)` untuk mencocokkan version tanpa menyimpan key.

## Canonical AAD

AAD dibuat oleh fungsi typed, length-prefixed/binary canonical—bukan concatenated string bebas.

```text
wrapped DEK: app-format | purpose=environment-dek | environment_id | dek_version | kek_version
current:     app-format | purpose=variable-current | service_id | environment_id | variable_id | version | dek_version
history:     app-format | purpose=variable-history | service_id | environment_id | variable_id | version | dek_version
proposal:    app-format | purpose=request-proposal | service_id | environment_id | request_id | item_id | item_revision | dek_version
TOTP:        app-format | purpose=totp-seed | user_id | crypto_version
```

Semua ID/version dibaca dari relational context yang tervalidasi. Memindah ciphertext/nonce antar row atau mengubah metadata menyebabkan authentication failure. Error decrypt tidak dibedakan ke client dan tidak memuat material kriptografi.

## Startup validation

Startup production gagal bila KEK hilang/invalid. Aplikasi membaca key registry/fingerprint dan mencoba membuka seluruh active wrapped DEK (atau seluruhnya untuk MVP yang kecil), memvalidasi panjang DEK serta maximum-one-active invariant. Restore startup menambah `PRAGMA integrity_check`, migration compatibility, dan representative decrypt sanity sebelum ready. Aplikasi tidak pernah membuat default/random replacement KEK saat boot.

## KEK rotation (rewrap only)

Precondition: Administrator + recent-auth high-impact; KEK baru terpasang pada primary path, KEK lama pada previous path; keduanya valid, berbeda, dan fingerprint baru belum konflik.

1. Buat operasi `KEK` berstatus `VALIDATING`; audit belum menyatakan sukses.
2. Baca seluruh active `environment_keys`; buka setiap wrapped DEK dengan previous KEK. Buka juga seluruh TOTP seed dengan purpose-derived key lama. Validasi material/fingerprint tanpa mengubah row.
3. Siapkan wrapped DEK dengan KEK baru serta re-encrypted TOTP seed dengan derived key baru; semuanya memakai nonce baru, target `kek_version`, dan AAD baru.
4. Dalam satu write transaction yang singkat, revalidasi source version/fingerprint, update seluruh active wrapped DEK dan encrypted TOTP seed, update key registry, tandai operation completed, dan append audit `ROTATE_KEK` tanpa material key.
5. Setelah commit, buka ulang seluruh wrapped DEK menggunakan primary KEK. Bila verifikasi post-commit gagal, readiness menjadi false dan runbook recovery memakai previous KEK/backup; jangan melakukan destructive fallback otomatis.
6. Operator menghapus previous KEK secret dari deployment setelah verifikasi sukses.

Kegagalan validasi sebelum commit menghasilkan zero database mutation. Environment value tidak didecrypt/re-encrypt pada KEK rotation. TOTP seed adalah system secret yang dienkripsi langsung di bawah purpose-derived KEK subkey, sehingga ia memang perlu di-encrypt ulang; ini tidak mengubah pemisahan KEK-vs-DEK untuk environment values.

## DEK rotation (re-encryption)

Precondition: target satu environment, active old DEK dapat dibuka, tidak ada rotation lain, Administrator recent-auth high-impact. Current values, seluruh history, dan seluruh proposal terenkripsi—termasuk request terminal—yang memakai old DEK termasuk scope. Implementasi monolith MVP memblokir seluruh unsafe application write selama maintenance rotation; login/logout dan resume rotation tetap tersedia. Read dapat berlangsung selama version-nya dapat ditelusuri.

Untuk dataset kecil, prefer satu transaction: generate/wrap new DEK → decrypt/re-encrypt setiap scoped record dengan nonce/AAD baru → verify → switch active version → null old wrapped material → audit → commit.

Untuk dataset besar, gunakan state machine batch yang crash-resumable:

```text
PREPARING -> MIGRATING -> VERIFYING -> COMMITTING -> COMPLETED
                                      `-> FAILED (old key retained)
```

- Insert new key sebagai `pending`; old tetap `active` dan usable.
- Setiap migrated ciphertext langsung menyimpan `dek_version=new`, jadi tidak ambigu setelah crash. Batch transaction berisi maksimum 64 row dan checkpoint count disimpan pada `key_rotation_operations`; resume menemukan pekerjaan tersisa dari referensi `dek_version=old`, tanpa cursor plaintext atau worker.
- Record direct-apply legacy yang pernah menyimpan salinan current-value blob di kolom proposal hanya diterima bila metadata internal dan relasi immutable version cocok secara ketat. Rotasi membukanya menggunakan current-value AAD relasional lama lalu langsung menulis ulang dengan proposal AAD target; request biasa tidak memakai fallback ini.
- Readers memilih DEK berdasarkan row `dek_version`, bukan hanya active flag. Writer untuk environment diblokir agar scope stabil.
- Verifikasi mencakup seluruh row scope, AEAD decrypt, relational/AAD metadata, count, dan tidak adanya old-version reference.
- Final transaction mengubah new key menjadi `active`, old menjadi `retired`, men-NULL-kan `wrapped_dek`/nonce lama, menandai operation complete, dan menulis audit.
- Bila gagal sebelum finalisasi, old wrapped key dan pending new key tetap tersedia untuk resume/rollback terkontrol. Rollback harus me-reencrypt row new-version kembali, bukan hanya mengganti flag. Tidak ada key material dihapus sebelum seluruh reference old version nol dan verifikasi sukses.

Operasi bersifat sinkron/maintenance pada MVP. UI menampilkan progress antar batch tetapi tidak bergantung pada background worker; disconnect tidak boleh membuat status ambigu dan Administrator dapat resume operasi berdasarkan checkpoint. Maintenance window direkomendasikan untuk history besar.

## Compromise response

- Suspected KEK leak: pasang KEK baru, lakukan KEK rotation, lalu nilai apakah DEK dan external credentials juga harus diputar. Rewrap saja tidak menyembuhkan plaintext yang sudah dicuri.
- Suspected DEK leak: DEK rotation target environment wajib mencakup current/history/proposal, lalu rotate real credentials di target systems dan deployment platform.
- Lost KEK: gunakan backup KEK yang disimpan terpisah. Tanpa itu ciphertext tidak dapat dipulihkan.

## Tests

Round trip; random nonce; wrong key/AAD/nonce/tampered ciphertext failure; cross-record swap failure; startup invalid key; KEK validation no-mutation failure; successful rewrap without value ciphertext changes; DEK rotation covers current/history/proposals; crash at every batch boundary; no old references before key destruction; concurrency/write blocking; audit contains metadata only.
