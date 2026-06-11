# Penjelasan Sederhana: AES-256-CBC dan HMAC-SHA256
## Versi Mudah Dipahami — Step by Step

---

# 1. AES-256 — Mengacak Data Agar Tidak Bisa Dibaca

## Apa itu AES?

AES (Advanced Encryption Standard) adalah cara **mengacak data** sehingga hanya orang yang punya kunci yang bisa membacanya kembali.

**Analogi:** Bayangkan kamu punya surat rahasia. AES seperti memasukkan surat itu ke dalam **brankas berkombinasi** — orang lain bisa melihat brankas-nya, tapi tidak bisa membaca isinya tanpa tahu kombinasinya.

```
Plaintext (bisa dibaca)          Ciphertext (tidak bisa dibaca)
"suhu: 25.5°C"        ──AES──►  "a7f3b2e1c9d8..."
                       ◄──AES──
                       (dengan kunci yang sama)
```

## Angka-angka Penting AES-256

| Istilah | Artinya |
|---------|---------|
| **256** | Panjang kunci = 256 bit = 32 karakter. Makin panjang, makin sulit ditebak |
| **Block** | AES memproses data per potongan **16 byte** (128 bit) sekaligus |
| **14 putaran** | Setiap potongan data diacak **14 kali berturut-turut** |

---

## Step-by-Step Enkripsi AES-256

### STEP 0 — Potong Data Menjadi Blok 16 Byte (Padding)

AES hanya bisa memproses data yang panjangnya **tepat kelipatan 16 byte**. Jika kurang, ditambahkan byte tambahan (padding).

```
Data asli: {"t":25.50,"h":68.20,"ts":1749380000000}
Panjang  : 46 byte ← bukan kelipatan 16!

Kelipatan 16 terdekat = 48
Kurang = 48 - 46 = 2 byte

Tambahkan 2 byte yang isinya angka "2":
[...data asli 46 byte...][02][02]
                          ↑ padding

Sekarang panjangnya 48 byte = 3 blok × 16 byte ✓
```

**Aturan PKCS7:** Jika kurang N byte, tambahkan N byte bernilai N. Sederhana!

---

### STEP 1 — Siapkan Kunci (Key Expansion)

Kunci asli 32 byte **diperluas** menjadi **15 kunci putaran** (round key). Ini seperti membuat 15 anak kunci dari 1 kunci induk.

```
Kunci Asli (32 byte)
"KunciRahasiaSkripsiDepoArsip2026"
         │
         ▼
   ┌─ Key Expansion ─┐
   │                  │
   ▼                  ▼
Round Key 0          ...         Round Key 14
(untuk awal)                     (untuk akhir)

Total: 15 round key, masing-masing 16 byte
```

**Mengapa diperluas?** Agar setiap putaran menggunakan material kunci yang **berbeda** — sehingga makin sulit dipecahkan.

---

### STEP 2 — Susun Data ke Matriks 4×4 (State)

Setiap blok 16 byte disusun ke dalam tabel 4 baris × 4 kolom. Inilah "papan kerja" AES.

```
16 byte data:
[7B][4B][2E][53][01][F4][A8][9C][E2][D8][31][15][B6][DA][21][FF]

Disusun per KOLOM:
┌────┬────┬────┬────┐
│ 7B │ 01 │ E2 │ B6 │  ← baris 0
│ 4B │ F4 │ D8 │ DA │  ← baris 1
│ 2E │ A8 │ 31 │ 21 │  ← baris 2
│ 53 │ 9C │ 15 │ FF │  ← baris 3
└────┴────┴────┴────┘
  ↑    ↑    ↑    ↑
 kol0 kol1 kol2 kol3
```

---

### STEP 3 — Campur dengan Kunci (AddRoundKey) — Round 0

Data di-XOR dengan Round Key 0. XOR adalah operasi bit:
- Sama → 0
- Beda → 1

```
Data:          Kunci:          Hasil:
  0 1 1 1        0 1 0 0        0 0 1 1
  ⊕               =
(jika bit sama → 0, jika beda → 1)
```

```
┌────┬────┬────┬────┐     ┌────┬────┬────┬────┐     ┌────┬────┬────┬────┐
│ 7B │ 01 │ E2 │ B6 │     │ 4B │ 2C │ A1 │ 3F │     │ 30 │ 2D │ 43 │ 89 │
│ 4B │ F4 │ D8 │ DA │  ⊕  │ 1A │ 9E │ 7B │ 55 │  =  │ 51 │ 6A │ A3 │ 8F │
│ 2E │ A8 │ 31 │ 21 │     │ 83 │ C7 │ 06 │ D2 │     │ AD │ 6F │ 37 │ F3 │
│ 53 │ 9C │ 15 │ FF │     │ 12 │ 45 │ 8D │ B1 │     │ 41 │ D9 │ 98 │ 4E │
└────┴────┴────┴────┘     └────┴────┴────┴────┘     └────┴────┴────┴────┘
      DATA                    ROUND KEY 0                  HASIL
```

> **Tujuan:** Mencampur data dengan kunci. Tanpa langkah ini, enkripsi bisa dibongkar tanpa kunci.

---

### STEP 4 sampai 17 — 14 Putaran Pengacakan

Setelah AddRoundKey awal, data melewati **14 putaran** yang masing-masing terdiri dari 4 operasi:

```
╔═══════════════════════════════════════════════════════╗
║               SATU PUTARAN AES                        ║
║                                                       ║
║  ① SubBytes    → Ganti setiap byte (substitusi)       ║
║  ② ShiftRows   → Geser baris ke kiri                  ║
║  ③ MixColumns  → Campur setiap kolom                  ║
║  ④ AddRoundKey → Campur dengan kunci putaran           ║
║                                                       ║
║  Ulangi 14 kali! (putaran ke-14 tanpa MixColumns)     ║
╚═══════════════════════════════════════════════════════╝
```

Mari kita bahas satu per satu:

---

#### ① SubBytes — Ganti Setiap Byte

Setiap byte diganti dengan byte lain menggunakan **tabel pengganti tetap** (S-Box).

**Analogi:** Seperti sandi rahasia anak-anak — "A jadi M, B jadi Z, C jadi K...". Tapi di AES, tabelnya 256 entri dan dirancang secara matematis agar sangat sulit dipecahkan.

```
Sebelum:                    Setelah:
┌────┬────┬────┬────┐      ┌────┬────┬────┬────┐
│ 30 │ 2D │ 43 │ 89 │      │ 04 │ D8 │ 1A │ A7 │
│ 51 │ 6A │ A3 │ 8F │  →   │ D1 │ 02 │ 0A │ 73 │
│ AD │ 6F │ 37 │ F3 │      │ 95 │ A8 │ 9A │ 0D │
│ 41 │ D9 │ 98 │ 4E │      │ 83 │ 35 │ 46 │ 2F │
└────┴────┴────┴────┘      └────┴────┴────┴────┘

Contoh: byte 30 → cari di tabel → hasilnya 04
        byte 51 → cari di tabel → hasilnya D1
        (setiap byte diganti secara INDEPENDEN)
```

> **Tujuan:** Membuat hubungan antara input dan output menjadi **serumit mungkin** (properti "confusion"). Ini seperti mengacak kartu — hubungan aslinya hilang.

---

#### ② ShiftRows — Geser Baris ke Kiri

Setiap baris digeser ke kiri dengan jumlah yang berbeda:

```
Baris 0: tidak bergerak
Baris 1: geser 1 langkah ke kiri
Baris 2: geser 2 langkah ke kiri
Baris 3: geser 3 langkah ke kiri

Sebelum:                     Setelah:
┌────┬────┬────┬────┐       ┌────┬────┬────┬────┐
│ 04 │ D8 │ 1A │ A7 │  ──►  │ 04 │ D8 │ 1A │ A7 │  (tetap)
│ D1 │ 02 │ 0A │ 73 │  ←1   │ 02 │ 0A │ 73 │ D1 │  (geser 1)
│ 95 │ A8 │ 9A │ 0D │  ←2   │ 9A │ 0D │ 95 │ A8 │  (geser 2)
│ 83 │ 35 │ 46 │ 2F │  ←3   │ 2F │ 83 │ 35 │ 46 │  (geser 3)
└────┴────┴────┴────┘       └────┴────┴────┴────┘
```

> **Tujuan:** Menyebar byte ke posisi berbeda. Sebelum ShiftRows, setiap kolom berisi byte dari kolom yang sama. Setelahnya, byte **tercampur antar kolom** — ini mempersiapkan untuk MixColumns.

---

#### ③ MixColumns — Campur Setiap Kolom

Setiap kolom (4 byte) dicampur dengan operasi perkalian matriks khusus. Hasilnya, **mengubah 1 byte** di kolom akan mengubah **keempat byte** di kolom tersebut.

```
Sebelum:           Proses:                    Setelah:
┌────┐                                        ┌────┐
│ 04 │         ┌──────────────────┐            │ ?? │
│ 02 │   ───►  │  Perkalian       │   ───►     │ ?? │
│ 9A │         │  Matriks Tetap   │            │ ?? │
│ 2F │         │  (dalam GF 2⁸)  │            │ ?? │
└────┘         └──────────────────┘            └────┘
kolom 0        × matriks campuran             kolom 0 baru

Ini dilakukan untuk SETIAP kolom (4 kolom total)
```

**Analogi:** Bayangkan 4 warna cat dicampur dengan resep tertentu — warna baru bergantung pada **semua** warna asli. Mengubah sedikit saja satu warna mengubah hasil campuran secara drastis.

> **Tujuan:** Membuat setiap byte output bergantung pada **semua byte dalam kolom** (properti "diffusion"). Bersama ShiftRows, ini memastikan setelah beberapa putaran, **setiap byte ciphertext bergantung pada seluruh byte plaintext**.

---

#### ④ AddRoundKey — Campur dengan Kunci Putaran

Sama seperti Step 3, state di-XOR dengan round key putaran saat ini.

```
Putaran 1 → XOR dengan Round Key 1
Putaran 2 → XOR dengan Round Key 2
...
Putaran 14 → XOR dengan Round Key 14
```

> Ini memastikan **setiap putaran menggunakan kunci yang berbeda**.

---

### Ringkasan 14 Putaran

```
Plaintext (1 blok = 16 byte)
    │
    ▼
AddRoundKey (Round Key 0)      ← campur dengan kunci awal
    │
    │    ╔══════════════════════════════════╗
    ├───►║  Putaran 1-13 (diulang 13×):    ║
    │    ║    ① SubBytes    → ganti byte   ║
    │    ║    ② ShiftRows   → geser baris  ║
    │    ║    ③ MixColumns  → campur kolom ║
    │    ║    ④ AddRoundKey → campur kunci  ║
    │    ╚══════════════════════════════════╝
    │
    │    ╔══════════════════════════════════╗
    └───►║  Putaran 14 (terakhir):         ║
         ║    ① SubBytes                   ║
         ║    ② ShiftRows                  ║
         ║    ③ AddRoundKey                ║
         ║    (TANPA MixColumns)           ║
         ╚══════════════╤═════════════════╝
                        │
                        ▼
               Ciphertext (16 byte)
```

**Mengapa putaran terakhir tanpa MixColumns?** Karena MixColumns di putaran terakhir tidak menambah keamanan dan menghilangkannya membuat proses enkripsi dan dekripsi menjadi simetris (lebih efisien).

---

## Mode CBC — Merangkai Blok yang Banyak

AES hanya bisa mengenkripsi **1 blok (16 byte)** sekaligus. Bagaimana jika data lebih panjang?

Mode **CBC (Cipher Block Chaining)** merangkai blok-blok dengan cara:

```
Setiap blok plaintext di-XOR dulu dengan ciphertext blok SEBELUMNYA,
baru kemudian dienkripsi.

Untuk blok pertama (yang belum ada ciphertext sebelumnya),
digunakan IV (Initialization Vector) — nilai acak 16 byte.
```

```
IV (acak)      Ciphertext 1       Ciphertext 2
  │               │                   │
  ▼               ▼                   ▼
┌────┐          ┌────┐              ┌────┐
│ IV │          │ C₁ │              │ C₂ │
└──┬─┘          └──┬─┘              └──┬─┘
   │               │                   │
   ▼               ▼                   ▼
Plaintext 1 ⊕ IV  Plaintext 2 ⊕ C₁   Plaintext 3 ⊕ C₂
   │               │                   │
   ▼               ▼                   ▼
╔══════╗        ╔══════╗            ╔══════╗
║ AES  ║        ║ AES  ║            ║ AES  ║
║ 14   ║        ║ 14   ║            ║ 14   ║
║round ║        ║round ║            ║round ║
╚══╤═══╝        ╚══╤═══╝            ╚══╤═══╝
   │               │                   │
   ▼               ▼                   ▼
Ciphertext 1    Ciphertext 2        Ciphertext 3
```

### Mengapa IV Harus Acak?

```
TANPA IV acak:
  Data sama + kunci sama = ciphertext SELALU SAMA
  → Penyerang: "Hmm, ciphertext ini pernah muncul kemarin,
                berarti suhunya sama seperti kemarin"
  → POLA TERBACA!

DENGAN IV acak per pengiriman:
  Data sama + kunci sama + IV beda = ciphertext SELALU BERBEDA
  → Penyerang: "Ciphertext ini berbeda dari kemarin...
                dan kemarin juga berbeda... tidak ada pola!"
  → AMAN ✓
```

---

## Dekripsi AES-256-CBC — Kebalikannya

Dekripsi adalah proses **membalik** semua langkah enkripsi:

| Enkripsi (maju) | Dekripsi (mundur) |
|-----------------|-------------------|
| SubBytes (ganti byte) | **InvSubBytes** (ganti balik pakai tabel kebalikan) |
| ShiftRows (geser kiri) | **InvShiftRows** (geser KANAN) |
| MixColumns (campur) | **InvMixColumns** (campur balik pakai matriks kebalikan) |
| AddRoundKey (XOR kunci) | **AddRoundKey** (XOR lagi — karena A ⊕ K ⊕ K = A) |

**Dekripsi CBC:**

```
Ciphertext 1       Ciphertext 2       Ciphertext 3
   │                   │                   │
   ▼                   ▼                   ▼
╔══════╗            ╔══════╗            ╔══════╗
║ AES  ║            ║ AES  ║            ║ AES  ║
║Decrypt║           ║Decrypt║           ║Decrypt║
╚══╤═══╝            ╚══╤═══╝            ╚══╤═══╝
   │                   │                   │
   ▼                   ▼                   ▼
 Hasil ⊕ IV         Hasil ⊕ C₁          Hasil ⊕ C₂
   │                   │                   │
   ▼                   ▼                   ▼
Plaintext 1         Plaintext 2         Plaintext 3
```

Setelah dekripsi, **padding dihapus** — baca byte terakhir untuk tahu berapa byte padding yang ditambahkan.

---

# 2. HMAC-SHA256 — Memastikan Data Tidak Diubah

## Apa itu HMAC?

HMAC (Hash-based Message Authentication Code) adalah cara membuat **stempel digital** pada data menggunakan **kunci rahasia**. Stempel ini membuktikan:
1. **Integritas** — data tidak diubah di perjalanan
2. **Autentikasi** — data benar dari pengirim yang sah (yang punya kunci)

**Analogi:** Bayangkan kamu mengirim surat dalam amplop. HMAC seperti **segel lilin dengan cap cincin pribadi**:
- Jika segel utuh → surat belum dibuka/diubah ✓
- Jika segel rusak → seseorang membuka/mengubah surat ✗
- Hanya kamu yang punya cincin cap → orang lain tidak bisa membuat segel palsu

## Mengapa Bukan SHA-256 Biasa? Mengapa Harus HMAC?

```
SHA-256 biasa (tanpa kunci):
  Siapapun bisa menghitung hash dari data apapun.
  
  Penyerang:
  1. Sadap data sensor: "suhu 35°C" + hash-nya
  2. Ubah jadi: "suhu 22°C"
  3. Hitung SHA-256 BARU dari "suhu 22°C" ← BISA!
  4. Kirim data palsu + hash baru ke server
  5. Server: "hash cocok, data valid!" ← TERTIPU!

HMAC-SHA256 (dengan kunci rahasia):
  Hanya yang punya KUNCI yang bisa membuat hash valid.
  
  Penyerang:
  1. Sadap data sensor: "suhu 35°C" + HMAC-nya
  2. Ubah jadi: "suhu 22°C"
  3. Coba hitung HMAC baru... TIDAK BISA tanpa kunci! ← GAGAL
  4. Server: "HMAC tidak cocok → DITOLAK!" ← AMAN ✓
```

---

## Step-by-Step HMAC-SHA256

HMAC sebenarnya **memanggil SHA-256 dua kali** — sekali untuk "inner hash" dan sekali untuk "outer hash". Ini yang membuatnya lebih kuat dari hash biasa.

### STEP 1 — Siapkan Kunci

```
Kunci HMAC: 32 byte (di proyek ini, berbeda dari kunci AES)

SHA-256 memproses per blok 64 byte.
Kunci 32 byte < 64 byte → tambahkan nol di belakang hingga 64 byte.

Kunci yang dipadding:
[K₁ K₂ K₃ ... K₃₂ 00 00 00 ... 00]
          32 byte      32 byte nol
└─────────── 64 byte ─────────────┘
```

### STEP 2 — Buat Inner Hash (Hash Pertama)

```
1. XOR kunci dengan ipad (byte 0x36 diulang 64 kali):
   
   Kunci:  [K₁   K₂   K₃  ... ]     (64 byte)
   ipad:   [0x36 0x36 0x36 ... ]     (64 byte)
   Hasil:  [K₁⊕36  K₂⊕36  ...]      (64 byte)

2. Gabungkan dengan pesan (M):
   
   inner_data = (Kunci ⊕ ipad) + Pesan
                 64 byte          n byte

   Di proyek ini, Pesan = IV + Ciphertext (Encrypt-then-MAC)

3. Hash dengan SHA-256:

   inner_hash = SHA-256(inner_data)
   Hasil: 32 byte
```

### STEP 3 — Buat Outer Hash (Hash Kedua)

```
1. XOR kunci dengan opad (byte 0x5C diulang 64 kali):
   
   Kunci:  [K₁   K₂   K₃  ... ]     (64 byte)
   opad:   [0x5C 0x5C 0x5C ... ]     (64 byte)
   Hasil:  [K₁⊕5C  K₂⊕5C  ...]      (64 byte)

2. Gabungkan dengan inner_hash:
   
   outer_data = (Kunci ⊕ opad) + inner_hash
                 64 byte          32 byte

3. Hash dengan SHA-256:

   HMAC = SHA-256(outer_data)
   Hasil: 32 byte ← INI TAG HMAC FINAL!
```

### Visualisasi Sederhana

```
Kunci ──────┬────────────────┐
            │                │
            ▼                ▼
       Kunci ⊕ ipad     Kunci ⊕ opad
            │                │
            ▼                │
      ┌───────────┐          │
      │Kunci⊕ipad │          │
      │  + Pesan   │          │
      └─────┬─────┘          │
            │                │
            ▼                │
       ╔═════════╗           │
       ║ SHA-256 ║           │
       ╚════╤════╝           │
            │                │
       inner_hash            │
       (32 byte)             │
            │                │
            │                ▼
            │         ┌───────────┐
            └────────►│Kunci⊕opad │
                      │+ inner    │
                      └─────┬─────┘
                            │
                            ▼
                       ╔═════════╗
                       ║ SHA-256 ║
                       ╚════╤════╝
                            │
                            ▼
                    HMAC Tag (32 byte)
                    "stempel digital"
```

### Mengapa Dua Kali Hash?

```
Jika hanya sekali: SHA-256(Kunci + Pesan)
→ Rentan terhadap "length extension attack"
  (penyerang bisa menambah data tanpa tahu kunci)

Dengan dua kali (inner + outer):
→ Serangan tersebut TIDAK mungkin
  karena hasil inner di-hash lagi dengan material kunci beda (opad)
```

---

## Apa yang Terjadi di Dalam SHA-256?

SHA-256 sendiri memproses data dalam 4 tahap besar:

### Tahap 1 — Padding Pesan

```
Pesan ditambahkan:
1. Satu bit "1"
2. Nol-nol sampai panjangnya pas
3. Panjang pesan asli (8 byte) di akhir

Total harus kelipatan 64 byte (512 bit)
```

### Tahap 2 — Mulai dari 8 Angka Awal

SHA-256 dimulai dari 8 angka tetap (konstanta dari akar kuadrat bilangan prima):

```
H₀ = 6A09E667    H₄ = 510E527F
H₁ = BB67AE85    H₅ = 9B05688C
H₂ = 3C6EF372    H₆ = 1F83D9AB
H₃ = A54FF53A    H₇ = 5BE0CD19
```

### Tahap 3 — Proses Setiap Blok 64 Byte (64 Putaran)

Untuk setiap blok 64 byte dari pesan:

```
1. Pecah 64 byte → 16 angka (word)
2. Perluas 16 angka → 64 angka (message schedule)
3. Jalankan 64 putaran kompresi:

   Setiap putaran menggunakan:
   ┌─────────────────────────────────────────────┐
   │  a, b, c, d, e, f, g, h  (8 variabel kerja) │
   │                                              │
   │  Ch(e,f,g) = "pilih f atau g berdasarkan e"  │
   │  Maj(a,b,c) = "ambil suara mayoritas"        │
   │  Σ₀(a) = putar dan campur bit-bit a          │
   │  Σ₁(e) = putar dan campur bit-bit e          │
   │                                              │
   │  Campur semua + W[t] + K[t]                  │
   │  Geser: h←g, g←f, ... b←a, a←hasil baru     │
   └─────────────────────────────────────────────┘
   
   Ulangi 64 kali!
```

### Tahap 4 — Gabungkan Hasil

```
Hash final = H₀ ‖ H₁ ‖ H₂ ‖ H₃ ‖ H₄ ‖ H₅ ‖ H₆ ‖ H₇
           = 8 × 4 byte = 32 byte = 256 bit

Ini selalu 32 byte, tidak peduli panjang input-nya.

Input 1 byte   → hash 32 byte
Input 1 MB     → hash 32 byte
Input 1 GB     → hash 32 byte
```

**Properti penting SHA-256:**
- **Satu arah:** Dari hash tidak bisa kembali ke data asli
- **Avalanche:** Ubah 1 bit input → ~50% bit hash berubah
- **Collision-resistant:** Hampir mustahil menemukan dua data berbeda dengan hash yang sama

---

# 3. Integrasi di Proyek Ini — Encrypt-then-MAC

## Alur Lengkap yang Mudah Dipahami

```
═══════════════════════════════════════════════════
  DI ESP32 (pengirim)
═══════════════════════════════════════════════════

  Sensor DHT22 membaca: suhu=25.5, kelembapan=68.2

  LANGKAH 1: Buat JSON
  ┌──────────────────────────────────────────────┐
  │ {"t":25.50,"h":68.20,"ts":1749380000000}     │
  │  ↑ suhu    ↑ kelembapan  ↑ waktu (milidetik) │
  └──────────────────────────────────────────────┘

  LANGKAH 2: Acak IV (16 byte acak)
  ┌──────────────────────────────────────────────┐
  │ A3 F1 7B 2E 9C 44 D8 01 B5 6F E2 8A 3C ...  │
  │ (dari hardware random number generator ESP32) │
  └──────────────────────────────────────────────┘

  LANGKAH 3: Enkripsi AES-256-CBC
  ┌────────────────────┐     ╔════════════╗     ┌──────────────────┐
  │ Plaintext JSON     │────►║ AES-256-CBC║────►│ Ciphertext (acak)│
  │ + padding PKCS7    │     ║ + IV + Key ║     │ 48 byte          │
  └────────────────────┘     ╚════════════╝     └──────────────────┘

  LANGKAH 4: Hitung HMAC-SHA256
  ┌──────────────────────────────┐     ╔═════════════╗     ┌────────────┐
  │ IV (16B) + Ciphertext (48B)  │────►║ HMAC-SHA256 ║────►│ Tag (32B)  │
  │ = 64 byte                    │     ║ + Kunci HMAC║     │ "stempel"  │
  └──────────────────────────────┘     ╚═════════════╝     └────────────┘

  LANGKAH 5: Gabung dan kirim
  ┌────────────┬──────────────────┬──────────────┐
  │  IV (16B)  │ Ciphertext (48B) │  HMAC (32B)  │
  └────────────┴──────────────────┴──────────────┘
                      │
               Base64 encode
                      │
                      ▼
            "aGVsbG8gd29ybGQ..."  (128 karakter)
                      │
               HTTP POST ke server
                      │
═══════════════════════╪═══════════════════════════
  DI JARINGAN (WiFi)   │
═══════════════════════╪═══════════════════════════
                       │
  Yang bisa dilihat    │  Yang TIDAK bisa dilihat
  oleh penyerang:      │  oleh penyerang:
  ┌────────────────┐   │
  │ String Base64  │   │  ✗ Suhu berapa
  │ acak dan panjang│   │  ✗ Kelembapan berapa
  │ "aGVsbG8g..."  │   │  ✗ Kapan data dibuat
  └────────────────┘   │  ✗ Kunci enkripsi
                       │  ✗ Kunci HMAC
═══════════════════════╪═══════════════════════════
  DI SERVER FLASK      │
═══════════════════════╪═══════════════════════════
                       │
  LANGKAH 6: Decode Base64
  ┌────────────┬──────────────────┬──────────────┐
  │  IV (16B)  │ Ciphertext (48B) │  HMAC (32B)  │
  └────────────┴──────────────────┴──────────────┘

  LANGKAH 7: ★ VERIFIKASI HMAC DULU ★
  ┌──────────────────────────────────────────────┐
  │ Hitung ulang: HMAC-SHA256(IV + Ciphertext)   │
  │ Bandingkan dengan HMAC yang diterima          │
  │                                               │
  │ Cocok?                                        │
  │   ✓ YA  → lanjut dekripsi                    │
  │   ✗ TIDAK → TOLAK! Log serangan. SELESAI.    │
  │            (dekripsi TIDAK dijalankan)        │
  └──────────────────────────────────────────────┘

  LANGKAH 8: Dekripsi AES-256-CBC (hanya jika HMAC cocok)
  ┌──────────────────┐     ╔════════════╗     ┌────────────────────┐
  │ Ciphertext (48B) │────►║AES-256-CBC ║────►│ Plaintext JSON     │
  │ + IV             │     ║ Decrypt    ║     │ - unpad PKCS7      │
  └──────────────────┘     ╚════════════╝     └────────────────────┘

  LANGKAH 9: Validasi Timestamp
  ┌──────────────────────────────────────────────┐
  │ Δt = |waktu_server - waktu_di_JSON|          │
  │                                               │
  │ Δt ≤ 60 detik?                               │
  │   ✓ YA  → data VALID, simpan ke database     │
  │   ✗ TIDAK → REPLAY ATTACK! Tolak.            │
  └──────────────────────────────────────────────┘
```

## Mengapa Urutan Encrypt-then-MAC?

```
┌────────────────────────────────────────────────────────────┐
│  Encrypt-then-MAC (yang digunakan di proyek ini):          │
│                                                            │
│  1. Enkripsi dulu → dapatkan ciphertext                    │
│  2. Hitung HMAC dari ciphertext                            │
│                                                            │
│  Keuntungan:                                               │
│  • Server CEK HMAC DULU sebelum dekripsi                   │
│  • Jika HMAC tidak cocok → langsung tolak                  │
│  • Dekripsi TIDAK PERNAH dijalankan untuk data palsu       │
│  • Serangan terhadap proses dekripsi = TIDAK MUNGKIN       │
│                                                            │
│  Ini urutan yang PALING AMAN dari 3 opsi yang ada.         │
└────────────────────────────────────────────────────────────┘
```

---

# 4. Ringkasan Satu Halaman

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│   AES-256-CBC (Mengacak Data)                       │
│   ─────────────────────────                         │
│   • Potong data → blok 16 byte                      │
│   • 14 putaran pengacakan:                          │
│     ① SubBytes  → ganti setiap byte (tabel S-Box)   │
│     ② ShiftRows → geser baris ke kiri               │
│     ③ MixColumns→ campur setiap kolom               │
│     ④ AddRoundKey→ XOR dengan kunci putaran          │
│   • Mode CBC → rangkai blok dengan IV acak          │
│   • Hasil: ciphertext acak yang tidak bisa dibaca   │
│                                                     │
│   → Menjawab: KERAHASIAAN (Confidentiality)         │
│                                                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│   HMAC-SHA256 (Stempel Digital)                     │
│   ─────────────────────────────                     │
│   • Ambil kunci + pesan (IV + ciphertext)           │
│   • Inner hash: SHA-256(kunci⊕ipad + pesan)         │
│   • Outer hash: SHA-256(kunci⊕opad + inner)         │
│   • Hasil: tag 32 byte yang HANYA bisa dibuat       │
│     oleh yang punya kunci                           │
│                                                     │
│   → Menjawab: INTEGRITAS + AUTENTIKASI              │
│                                                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│   Encrypt-then-MAC (Urutan Proses)                  │
│   ───────────────────────────────                   │
│   Kirim: Enkripsi → HMAC → Gabung → Kirim          │
│   Terima: Cek HMAC → (jika cocok) Dekripsi          │
│                                                     │
│   → HMAC dicek SEBELUM dekripsi                     │
│   → Data palsu TIDAK PERNAH didekripsi              │
│                                                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│   Validasi Timestamp (Anti-Replay)                  │
│   ──────────────────────────────                    │
│   • Timestamp disematkan di plaintext JSON          │
│   • Server cek: |waktu_server - timestamp| ≤ 60s?  │
│   • Jika lewat → tolak sebagai replay attack        │
│                                                     │
│   → Menjawab: ANTI-REPLAY                           │
│                                                     │
└─────────────────────────────────────────────────────┘
```
