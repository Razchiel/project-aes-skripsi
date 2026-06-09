import sqlite3
from datetime import datetime
import hashlib
import secrets

DB_NAME = "mikroklimat.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sensor_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            suhu REAL, kelembapan REAL, waktu_dekripsi_ms REAL, status TEXT,
            iv_hex TEXT, ciphertext_hex TEXT, hmac_tag_hex TEXT,
            payload_base64 TEXT, plaintext_json TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            jenis_serangan TEXT, detail TEXT, status TEXT,
            iv_hex TEXT, ciphertext_hex TEXT,
            hmac_tag_hex TEXT,
            hmac_dihitung_hex TEXT,
            payload_base64 TEXT, plaintext_json TEXT, delta_ms INTEGER
        )
    ''')

    _migrasi_kolom(cursor)
    conn.commit()
    conn.close()
    
    init_admin_table()

def _migrasi_kolom(cursor):
    migrations = [
        "ALTER TABLE sensor_data ADD COLUMN iv_hex TEXT",
        "ALTER TABLE sensor_data ADD COLUMN ciphertext_hex TEXT",
        "ALTER TABLE sensor_data ADD COLUMN hmac_tag_hex TEXT",
        "ALTER TABLE sensor_data ADD COLUMN payload_base64 TEXT",
        "ALTER TABLE sensor_data ADD COLUMN plaintext_json TEXT",
        "ALTER TABLE attack_log ADD COLUMN iv_hex TEXT",
        "ALTER TABLE attack_log ADD COLUMN ciphertext_hex TEXT",
        "ALTER TABLE attack_log ADD COLUMN hmac_tag_hex TEXT",
        "ALTER TABLE attack_log ADD COLUMN hmac_dihitung_hex TEXT",
        "ALTER TABLE attack_log ADD COLUMN payload_base64 TEXT",
        "ALTER TABLE attack_log ADD COLUMN plaintext_json TEXT",
        "ALTER TABLE attack_log ADD COLUMN delta_ms INTEGER",
        "ALTER TABLE attack_log ADD COLUMN avalanche_persen REAL",
        # Kolom metrik skripsi M1 & M2
        "ALTER TABLE sensor_data ADD COLUMN waktu_enkripsi_ms REAL",
        "ALTER TABLE sensor_data ADD COLUMN total_waktu_ms REAL",
        "ALTER TABLE sensor_data ADD COLUMN overhead_bytes INTEGER",
    ]
    for sql in migrations:
        try:
            cursor.execute(sql)
        except Exception:
            pass

def simpan_data_sensor(suhu, kelembapan, waktu_dekripsi_ms, status, crypto_info=None,
                       waktu_enkripsi_ms=None, total_waktu_ms=None, overhead_bytes=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    waktu_sekarang = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ci = crypto_info or {}
    cursor.execute('''
        INSERT INTO sensor_data
            (timestamp, suhu, kelembapan, waktu_dekripsi_ms, status,
             iv_hex, ciphertext_hex, hmac_tag_hex, payload_base64, plaintext_json,
             waktu_enkripsi_ms, total_waktu_ms, overhead_bytes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (waktu_sekarang, suhu, kelembapan, waktu_dekripsi_ms, status,
          ci.get('iv_hex'), ci.get('ciphertext_hex'), ci.get('hmac_tag_hex'),
          ci.get('payload_base64'), ci.get('plaintext_json'),
          waktu_enkripsi_ms, total_waktu_ms, overhead_bytes))
    conn.commit()
    conn.close()

def catat_log_serangan(jenis_serangan, detail, status, crypto_info=None, avalanche_persen=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    waktu_sekarang = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ci = crypto_info or {}
    cursor.execute('''
        INSERT INTO attack_log
            (timestamp, jenis_serangan, detail, status,
             iv_hex, ciphertext_hex, hmac_tag_hex, hmac_dihitung_hex,
             payload_base64, plaintext_json, delta_ms, avalanche_persen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        waktu_sekarang, jenis_serangan, detail, status,
        ci.get('iv_hex'), ci.get('ciphertext_hex'),
        ci.get('hmac_tag_hex'), ci.get('hmac_dihitung_hex'),
        ci.get('payload_base64'), ci.get('plaintext_json'),
        ci.get('delta_ms'), avalanche_persen
    ))
    conn.commit()
    conn.close()

def ambil_data_terbaru(limit=200):
    """Mengambil data sensor terbaru untuk ditampilkan di web dashboard."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row # Agar output berupa dictionary, bukan tuple
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM sensor_data ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def ambil_log_serangan(limit=200):
    """Mengambil log serangan terbaru untuk tabel security dashboard."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM attack_log ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def ambil_statistik():
    """Menghitung statistik performa kriptografi untuk dashboard.
    
    Metrik yang dihitung:
      M1 — Waktu Komputasi (rata-rata enkripsi, dekripsi, total)
      M2 — Overhead Ukuran Data (rata-rata overhead bytes)
      M4 — Success Rate (paket terverifikasi / total seluruh paket)
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Metrik waktu dari data sensor yang berhasil (M1 & M2)
    cursor.execute('''
        SELECT COUNT(*),
               AVG(waktu_dekripsi_ms), MIN(waktu_dekripsi_ms), MAX(waktu_dekripsi_ms),
               AVG(waktu_enkripsi_ms), AVG(total_waktu_ms), AVG(overhead_bytes)
        FROM sensor_data
    ''')
    row = cursor.fetchone()
    total_paket = row[0] or 0
    avg_dekripsi = round(row[1], 2) if row[1] else 0
    min_dekripsi = round(row[2], 2) if row[2] else 0
    max_dekripsi = round(row[3], 2) if row[3] else 0
    avg_enkripsi = round(row[4], 2) if row[4] else 0
    avg_total    = round(row[5], 2) if row[5] else 0
    avg_overhead = round(row[6], 1) if row[6] else 0
    
    # Total serangan yang tercatat
    cursor.execute('SELECT COUNT(*) FROM attack_log')
    total_serangan = cursor.fetchone()[0] or 0
    
    # M4 — Success Rate (guard division by zero)
    total_semua_paket = total_paket + total_serangan
    if total_semua_paket > 0:
        success_rate = round((total_paket / total_semua_paket) * 100, 1)
    else:
        success_rate = 0.0
    
    conn.close()
    
    return {
        "total_paket": total_paket,
        "total_serangan": total_serangan,
        "rata_rata_dekripsi": avg_dekripsi,
        "min_dekripsi": min_dekripsi,
        "max_dekripsi": max_dekripsi,
        "rata_rata_enkripsi": avg_enkripsi,
        "rata_rata_total": avg_total,
        "rata_rata_overhead": avg_overhead,
        "success_rate": success_rate
    }

def ambil_data_chart_gabungan(limit=50):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT timestamp, suhu, kelembapan, status, 'sensor' as sumber
        FROM sensor_data
        UNION ALL
        SELECT timestamp, NULL as suhu, NULL as kelembapan, 'Attack' as status, 'attack' as sumber
        FROM attack_log
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def ambil_semua_data_sensor():
    """Mengambil SEMUA data sensor untuk keperluan export CSV."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM sensor_data ORDER BY id ASC')
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def ambil_semua_log_serangan():
    """Mengambil SEMUA log serangan untuk keperluan export CSV."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM attack_log ORDER BY id ASC')
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def reset_semua_data():
    conn = sqlite3.connect(DB_NAME)
    conn.execute('DELETE FROM sensor_data')
    conn.execute('DELETE FROM attack_log')
    conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('sensor_data', 'attack_log')")
    conn.commit()
    conn.close()

def init_admin_table():
    """Buat tabel admin_users jika belum ada."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    ''')
    conn.commit()

    # Buat akun admin default jika tabel masih kosong
    cursor.execute("SELECT COUNT(*) FROM admin_users")
    if cursor.fetchone()[0] == 0:
        _buat_admin(cursor, "admin", "admin123")
        print("[DB] Akun default dibuat: admin / admin123")

    conn.commit()
    conn.close()

def _buat_admin(cursor, username, password):
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    cursor.execute(
        "INSERT INTO admin_users (username, password_hash, salt) VALUES (?, ?, ?)",
        (username, password_hash, salt)
    )

def verifikasi_admin(username, password):
    """Return True jika username & password cocok, sekaligus update last_login."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin_users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return False

    password_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
    if password_hash == user['password_hash']:
        cursor.execute(
            "UPDATE admin_users SET last_login = ? WHERE username = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username)
        )
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False

def daftar_admin():
    """Ambil semua akun admin (tanpa hash) untuk manajemen."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, created_at, last_login FROM admin_users ORDER BY id")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def tambah_admin(username, password):
    """Tambah akun admin baru. Return False jika username sudah ada."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        _buat_admin(cursor, username, password)
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def hapus_admin(admin_id):
    """Hapus akun admin berdasarkan id. Tidak bisa hapus jika hanya 1 admin."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM admin_users")
    if cursor.fetchone()[0] <= 1:
        conn.close()
        return False, "Minimal harus ada 1 admin."
    cursor.execute("DELETE FROM admin_users WHERE id = ?", (admin_id,))
    conn.commit()
    conn.close()
    return True, "Admin dihapus."