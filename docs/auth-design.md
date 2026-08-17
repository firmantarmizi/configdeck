# Authentication Design

Status: final design baseline untuk Phase 1.

## Identity dan password

Email dinormalisasi dengan trim + lowercase untuk lookup/uniqueness; jangan melakukan transformasi Unicode yang mengubah mailbox secara spekulatif. Password disimpan sebagai PHC string Argon2id. Parameter dipilih dan dibenchmark pada target deployment agar verifikasi cukup mahal tetapi tetap aman dalam limit 256 MB; parameter dan library version dicatat sehingga hash dapat di-rehash setelah login bila policy berubah.

Bootstrap Administrator hanya berjalan bila tabel `users` kosong dan kedua variable bootstrap tersedia. Setelah berhasil, password tidak diproses lagi pada restart. UI/log startup mengingatkan untuk menghapus variable bootstrap dari deployment. Setelah enrollment TOTP, database baru mewajibkan authenticated organization setup sebelum halaman aplikasi normal; database existing ditandai sudah onboard oleh migration agar upgrade tidak mengunci user.

Account baru dari bootstrap atau `Users & Access` ditandai `must_change_password`. TOTP yang diwajibkan role diselesaikan lebih dahulu, lalu session hanya boleh membuka halaman ganti password sampai initial password berhasil diganti. Perubahan password menaikkan `auth_version`, mencabut seluruh session termasuk session saat ini, mencatat audit tanpa credential, dan meminta login ulang. Migration tidak memaksa existing account agar upgrade tidak menyebabkan lockout tak terduga.

## Login flow

1. Tentukan client identity dari socket peer atau trusted proxy policy, bukan langsung dari `X-Forwarded-For`.
2. Terapkan rate limit per client dan exponential backoff per normalized account key. Response tetap generik.
3. Verifikasi password Argon2id. Dummy hash digunakan untuk email yang tidak ada guna mengurangi account enumeration.
4. Operator/Administrator wajib memasukkan TOTP. Contributor wajib bila user mengaktifkan TOTP atau setting organisasi mewajibkannya.
5. Verifikasi TOTP dengan time window sempit dan tolak timestep yang sama/lebih lama dari `totp_last_used_step` agar code tidak direplay.
6. Buat session ID 256-bit dari CSPRNG; kirim raw token hanya melalui cookie, simpan `SHA-256(token)` di database.
7. Catat `auth_version` user pada session dan rotate cookie/session setelah autentikasi sukses.

TOTP seed dienkripsi at rest menggunakan ChaCha20-Poly1305 dan purpose-derived authentication key dari KEK aktif, dengan AAD yang mengikat `user_id`, purpose `totp-seed`, dan crypto format version. Seed tidak ditampilkan lagi setelah enrollment selesai. Enrollment memerlukan konfirmasi satu code valid sebelum diaktifkan. Recovery code tidak termasuk MVP; Administrator menggunakan prosedur reset TOTP yang diaudit dan mencabut semua session user.

Halaman enrollment menampilkan QR TOTP yang dibuat in-process dari provisioning URI dan di-embed sebagai SVG data URI. Tidak ada QR API/CDN eksternal. Setup key manual dan provisioning URI tetap tersedia sebagai fallback, dan seluruh response enrollment memakai `no-store`.

## Session model

Cookie production:

```text
__Host-configdeck_session=<opaque random token>; Path=/; Secure; HttpOnly; SameSite=Strict
```

Tidak ada `Domain`; prefix `__Host-` mengikat cookie pada host. Development HTTP harus memakai nama/config cookie eksplisit yang hanya dapat diaktifkan dalam development mode; aplikasi tidak boleh diam-diam menurunkan keamanan production.

Database hanya menyimpan token hash, user ID, created/last-seen/idle/absolute expiry, privileged-auth timestamp/level, auth version snapshot, dan metadata perangkat yang diminimalkan. Session lookup menggunakan hash dan constant-time comparison pada material security-sensitive. Last-seen update dibatasi intervalnya agar tidak menulis SQLite pada setiap asset/request.

Default awal yang dapat dikonfigurasi dengan batas aman:

- idle timeout: 30 menit;
- absolute timeout: 12 jam;
- recent-auth biasa: 5 menit;
- recent-auth high-impact (restore/rotation): 5 menit dan tidak boleh lebih longgar;
- session cleanup dilakukan oportunistik saat login/traffic admin, tanpa worker wajib.

Logout menghapus row server-side dan expire cookie. Password, role, active state, service access, atau TOTP reset menaikkan `users.auth_version`; mismatch membatalkan session. Perubahan password dan privilege mencabut semua session user, lalu aksi yang memerlukan kelanjutan membuat session baru melalui login.

Perubahan role, active state, dan reset TOTP oleh Administrator membutuhkan recent-auth. Administrator tidak dapat mengubah role/status dirinya sendiri atau mereset TOTP sendiri melalui daftar account, dan active Administrator terakhir dilindungi dari demotion/deactivation.

## Recent authentication

Recent-auth adalah step-up di dalam session yang masih valid:

1. POST form dengan CSRF valid.
2. Verifikasi password; verifikasi TOTP bila enrolled/required. Operator/Admin selalu TOTP.
3. Rotate session ID untuk mencegah fixation, simpan `privileged_authenticated_at` dan assurance level.
4. Redirect ke opaque, server-validated continuation target; jangan menerima arbitrary external URL.
5. Operasi sensitif memeriksa capability dan freshness kembali tepat sebelum decrypt/commit.

Recent-auth dipicu just-in-time dari tindakan sensitif, bukan sebagai menu atau kenaikan akses proaktif. Account menu hanya boleh menampilkan status session. Jika POST administrasi user memerlukan recent-auth, aplikasi mengarahkan ke konfirmasi identitas lalu kembali ke daftar tanpa menyimpan atau memutar ulang payload; Administrator mengirim ulang tindakan secara eksplisit setelah verifikasi.

Reveal/copy/export, previous restricted value, restricted fulfillment/import, backup, restore intent, dan KEK/DEK rotation memerlukan recent-auth. High-impact action juga meminta confirmation yang menyebut target, tetapi tidak memasukkan secret ke halaman atau log.

## CSRF

Setiap session memiliki random CSRF secret. Hanya hash disimpan di database; token raw hadir pada server-rendered form/HTMX header dan tidak masuk cookie terpisah atau browser storage. Semua POST/PUT/PATCH/DELETE memerlukan token valid yang terikat session. Verifikasi Origin/Fetch Metadata dipakai sebagai defense-in-depth; token tetap kontrol utama. Login dan recent-auth juga dilindungi dari login CSRF melalui pre-auth CSRF cookie/session berumur pendek atau signed nonce yang setara, diputuskan saat implementasi dengan test.

## Failure dan leakage controls

- Login response tidak membedakan user tidak ada, password salah, TOTP salah, inactive, atau backoff aktif.
- Password/TOTP tidak pernah muncul di log, audit metadata, URL, flash cookie, atau validation echo.
- Semua halaman authenticated memakai cache policy privat; response yang memuat plaintext restricted value memakai `no-store` dan `Pragma: no-cache`.
- Secret reveal menggunakan POST dan fragment minimal. Plaintext tidak dimasukkan ke global JS, DOM tersembunyi permanen, localStorage, sessionStorage, atau IndexedDB.
- Session token tidak diterima lewat query/body dan tidak dikirim ke API lain.
- Re-auth error tidak membocorkan apakah password atau TOTP yang salah.

## Test minimum

Password correct/incorrect/dummy path; required TOTP and replay rejection; session token hashing; idle/absolute expiry; logout; cookie attributes; session rotation; auth-version invalidation; CSRF cross-session rejection; recent-auth expiration and capability independence; trusted-proxy identity; throttling without permanent account lockout.
