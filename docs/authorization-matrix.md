# Authorization Matrix

Semua pemeriksaan dilakukan di backend untuk SSR dan API. `service access` berarti row aktif pada `user_service_access`. Recent-auth tidak memberikan capability baru; ia hanya syarat tambahan untuk operasi sensitif.

Legenda: **Ya** = diizinkan; **Scope** = hanya service yang ditugaskan; **RA** = wajib recent-auth password + TOTP; **Tidak** = ditolak.

| Capability / operasi | Contributor | Operator | Administrator |
|---|---:|---:|---:|
| Login/logout, lihat profil sendiri | Ya | Ya + TOTP login | Ya + TOTP login |
| Ganti password sendiri | Ya; initial password wajib diganti | Ya; initial password wajib diganti | Ya; initial password wajib diganti |
| Lihat daftar service/environment | Scope | Ya | Ya |
| Lihat key/metadata/status/history metadata | Scope | Ya | Ya |
| Baca/copy value `public` | Scope | Ya | Ya |
| Baca/copy value `restricted` | Tidak | RA | RA |
| Lihat previous restricted version | Tidak | RA | RA |
| Preview/copy/download resolved `.env` bila ada restricted value | Tidak | RA | RA |
| Export yang terbukti hanya berisi public value | Tidak pada MVP | RA | RA |
| Buat change set ADD/UPDATE/DELETE | Scope | Ya | Ya |
| Submit proposed restricted value | Scope; write-only setelah submit | Ya | Ya |
| Lihat proposed restricted value setelah submit | Tidak | RA | RA |
| Fulfill `OPERATOR_PROVIDED` value | Tidak | RA bila restricted | RA bila restricted |
| Approve/reject request | Tidak | Ya | Ya |
| Preview resulting config request | Tidak | RA | RA |
| Mark applied | Tidak | Ya; RA bila operasi membuka/copy restricted | Ya; RA bila operasi membuka/copy restricted |
| Direct add/edit/delete current registry | Tidak | Ya | Ya |
| Import `.env` | Tidak | RA | RA |
| Lihat audit log operasional | Tidak | Ya | Ya |
| Manage service/environment metadata | Tidak | Tidak | Ya |
| Manage users/roles/service access/settings | Tidak | Tidak | Ya; role/status/TOTP reset memerlukan RA |
| Create backup / restore intent | Tidak | Tidak | RA |
| Rotate KEK / DEK | Tidak | Tidak | RA dengan window ketat |

## Policy invariants

- Inactive user selalu ditolak dan semua session-nya dianggap invalid.
- Contributor membutuhkan service access pada setiap read dan request, termasuk lookup nested resource.
- Operator dan Administrator memiliki global service access sesuai spec; scope organisasi tunggal tetap diterapkan.
- `visibility=restricted` tidak pernah didecrypt untuk Contributor, termasuk bila Contributor adalah requester/creator.
- DELETE tidak membutuhkan proposed value; ADD/UPDATE harus memiliki encrypted value sebelum ready.
- Hanya change set `READY_TO_APPLY` yang dapat dipreview sebagai resulting config dan di-apply.
- Approver/applier boleh sama pada MVP; audit menyimpan kedua aksi. Four-eyes approval tidak diwajibkan spec.
- Self-service privilege escalation, perubahan role sendiri, dan penghapusan/penonaktifan Administrator aktif terakhir ditolak.
- Perubahan password, role, active state, service access, atau TOTP menaikkan `auth_version`/mencabut session terkait.
- Initial password account baru wajib diganti sebelum route aplikasi normal; perubahan berhasil selalu meminta login ulang.
- Endpoint unauthorized tidak mengungkap plaintext, ciphertext, nonce, maupun perbedaan detail error sensitif.

## Audit minimum

Successful reveal/copy/export, request lifecycle, direct variable mutation, access/user/admin changes, backup/restore intent, dan rotations wajib diaudit. Login failure dicatat secara rate-limited dengan metadata aman. Audit tidak pernah memuat value, password, TOTP code/seed, token, KEK, atau DEK.
