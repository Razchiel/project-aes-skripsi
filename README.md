# Implementasi AES-256-CBC dan HMAC-SHA256 untuk Pengamanan Data Sensor pada Sistem Monitoring Lingkungan Berbasis IoT

**Tugas Akhir** — Program Studi Rekayasa Sistem Komputer, FMIPA, Universitas Tanjungpura Pontianak

---

## Deskripsi

Sistem keamanan kriptografi untuk melindungi transmisi data sensor suhu dan kelembapan pada sistem monitoring mikroklimat di **Depo Arsip Dinas Perpustakaan dan Kearsipan Provinsi Kalimantan Barat**.

Menggunakan arsitektur **Encrypt-then-MAC**:
- **AES-256-CBC** — menjamin kerahasiaan data (confidentiality)
- **HMAC-SHA256** — menjamin integritas dan autentikasi data (integrity & authentication)
- **Validasi timestamp** — mencegah replay attack (anti-replay window 60 detik)

## Arsitektur Sistem

```
┌──────────────────────┐
│   ESP32 + DHT22      │
│                      │
│  Baca suhu & RH      │
│  Enkripsi AES-256    │
│  Hitung HMAC-SHA256  │
│  Kirim via HTTP POST │
└──────────┬───────────┘
           │  Payload: Base64(IV + Ciphertext + HMAC)
           │
           ▼
┌──────────────────────┐
│   Flask Server       │
│                      │
│  Verifikasi HMAC     │─── ✗ Mismatch → Tolak (403) + Log serangan
│  Dekripsi AES-256    │
│  Validasi timestamp  │─── ✗ Expired → Tolak (replay attack)
│  Simpan ke SQLite    │─── ✓ Valid → Dashboard + Database
└──────────────────────┘
```

## Struktur Format Payload

```
┌────────────┬──────────────────┬──────────────┐
│  IV (16B)  │  Ciphertext (nB) │  HMAC (32B)  │
└────────────┴──────────────────┴──────────────┘
              ↓ Base64 encode ↓
         String payload dikirim via JSON
```

## Struktur Proyek

```
project/
├── app.py              # Flask server — routing, API, simulasi serangan
├── crypto.py           # Modul kriptografi — AES-256-CBC, HMAC-SHA256, avalanche
├── database.py         # SQLite — skema, CRUD, admin management
├── requirements.txt    # Dependensi Python
│
├── static/
│   ├── main.js         # Dashboard controller — chart, polling, modal, simulasi
│   └── style.css       # Dark mode design system
│
├── templates/
│   ├── index.html      # Dashboard utama — monitoring & simulasi
│   ├── login.html      # Halaman login admin
│   └── db_viewer.html  # Database viewer (phpMyAdmin-like)
│
└── mikroklimat.db      # SQLite database (auto-generated)
```

## Instalasi

### Prasyarat
- Python 3.10+

### Langkah

```bash
# 1. Clone repository
git clone <repository-url>
cd project

# 2. (Opsional) Buat virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# 3. Install dependensi
pip install -r requirements.txt

# 4. Jalankan server
python app.py
```

Server akan berjalan di `http://127.0.0.1:5000`

## Halaman Aplikasi

| URL | Halaman | Keterangan |
|-----|---------|------------|
| `/` | Dashboard Utama | Monitoring real-time, grafik sensor, simulasi serangan |
| `/login` | Login Admin | Autentikasi untuk akses database viewer |
| `/db` | Database Viewer | Inspeksi tabel, detail record, manajemen admin |

## API Endpoints

### Data Sensor

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| `POST` | `/api/sensor` | Terima data terenkripsi dari ESP32 |
| `GET` | `/api/sensor/latest` | Ambil data sensor terbaru (paginated) |
| `GET` | `/api/sensor/gabungan` | Data gabungan sensor + serangan untuk grafik |
| `GET` | `/api/stats` | Statistik ringkasan (total, verified, attacks) |
| `GET` | `/api/export/csv` | Export seluruh data ke CSV |

### Simulasi

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| `POST` | `/api/simulate` | Simulasi pengiriman data normal |
| `POST` | `/api/simulate/attack` | Simulasi data tampering (modifikasi ciphertext) |
| `POST` | `/api/simulate/replay` | Simulasi replay attack (timestamp kadaluarsa) |

### Log Keamanan

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| `GET` | `/api/attacks` | Ambil log serangan terbaru (paginated) |
| `GET` | `/api/attack/<id>` | Detail satu serangan |

### Admin & Database

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| `POST` | `/login` | Proses login admin |
| `GET` | `/logout` | Logout admin |
| `POST` | `/api/reset` | Reset seluruh database |
| `GET` | `/api/db/<table>` | Ambil data tabel (paginated + search) |
| `POST` | `/api/admin/tambah` | Tambah admin baru |
| `DELETE` | `/api/admin/hapus/<id>` | Hapus admin |

## Fitur Dashboard

- **Security Banner** — status keamanan real-time (Safe / Danger)
- **Statistik** — suhu terakhir, kelembapan, data terverifikasi, serangan terdeteksi, success rate, overhead
- **Tabel Sensor Data** — data terverifikasi dengan pagination
- **Tabel Attack Log** — log serangan dengan detail HMAC mismatch
- **Grafik Real-time** — Chart.js dengan penanda titik serangan (merah) vs normal (biru/hijau)
- **Simulasi Serangan** — 3 tombol: Normal, Tampering, Replay
- **Modal Detail** — klik baris tabel untuk melihat IV, ciphertext, HMAC, plaintext JSON
- **Export CSV** — unduh seluruh data

## Metrik Evaluasi

| Kode | Metrik | Rumus |
|------|--------|-------|
| M1 | Waktu Komputasi | T_total = T_enkripsi + T_dekripsi (ms) |
| M2 | Overhead Ukuran Data | O = S_payload − S_plaintext (byte) |
| M3 | Avalanche Effect | AE = (B_diff / 256) × 100% |
| M4 | Success Rate Dekripsi | SR = (N_valid / N_total) × 100% |

## Skenario Pengujian Keamanan

| Kode | Skenario | Menguji |
|------|----------|---------|
| S1 | Eavesdropping (Wireshark) | AES-256-CBC → data tidak terbaca |
| S2 | Data Tampering | HMAC-SHA256 → modifikasi terdeteksi |
| S3 | Replay Attack | Timestamp window → paket expired ditolak |

## Tech Stack

| Komponen | Teknologi |
|----------|-----------|
| Backend | Python 3 + Flask |
| Kriptografi | PyCryptodome (AES, HMAC, SHA256) |
| Database | SQLite |
| Frontend | HTML5, CSS3 (dark mode), JavaScript (vanilla) |
| Grafik | Chart.js |
| Hardware | ESP32 DevKit V1 + DHT22 (kolaborasi) |
| Library ESP32 | mbedTLS (built-in) |

## Parameter Kriptografi

| Parameter | Nilai |
|-----------|-------|
| Algoritma Enkripsi | AES-256-CBC (FIPS 197) |
| Algoritma Autentikasi | HMAC-SHA256 (RFC 2104) |
| Panjang Kunci | 32 byte (256 bit) — pre-shared key |
| IV | 16 byte acak per paket |
| Padding | PKCS7 |
| Skema | Encrypt-then-MAC |
| Anti-Replay | Timestamp window ≤ 60 detik |

## Referensi Standar

- **SNI 7330:2009** — Parameter ideal ruang arsip: suhu 18–22°C, kelembapan 45–55% RH
- **NIST FIPS 197** — Advanced Encryption Standard (AES)
- **RFC 2104** — HMAC: Keyed-Hashing for Message Authentication

## Kredensial Default

| Username | Password |
|----------|----------|
| `admin` | `admin123` |

> ⚠️ Segera ubah password default setelah deployment.

## Lisensi

Proyek ini merupakan bagian dari Tugas Akhir dan ditujukan untuk keperluan akademis.

---

**Peneliti:** Alimmul Hafidz — Rekayasa Sistem Komputer, FMIPA, Universitas Tanjungpura Pontianak
