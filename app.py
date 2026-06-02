from flask import Flask, request, jsonify, render_template, make_response, session, redirect, url_for
import crypto
import database
import random
import base64 as b64
import csv
import io
import sqlite3
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # session cookie enkripsi

# Inisialisasi database saat aplikasi pertama kali dijalankan
database.init_db()

# Storage untuk simulasi replay attack
_last_valid_payload = None

# ==========================================
# ENDPOINT UNTUK ESP32 (Menerima Data)
# ==========================================
@app.route('/data', methods=['POST'])
def terima_data_esp32():
    # Mengambil payload Base64 yang dikirim ESP32
    # Format JSON yang diharapkan dari ESP32: {"payload": "base64_string_disini"}
    data_masuk = request.get_json()
    
    if not data_masuk or 'payload' not in data_masuk:
        return jsonify({"status": "error", "pesan": "Payload tidak ditemukan!"}), 400
    
    payload_base64 = data_masuk['payload']
    
    # 1. Lakukan proses verifikasi HMAC & Dekripsi AES
    sukses, hasil, waktu_ms, status_integritas, crypto_info = crypto.proses_payload_esp32(payload_base64)
    
    if sukses:
        # Jika berhasil didekripsi dan HMAC valid
        # Asumsi plaintext JSON: {"t": 25.5, "h": 68.2}
        suhu = hasil.get('t', 0.0)
        kelembapan = hasil.get('h', 0.0)
        
        # 2. Simpan ke database
        database.simpan_data_sensor(suhu, kelembapan, waktu_ms, status_integritas, crypto_info)
        
        return jsonify({
            "status": "success", 
            "pesan": "Data aman dan berhasil disimpan.",
            "waktu_dekripsi_ms": round(waktu_ms, 2)
        }), 200
        
    else:
        # Jika GAGAL (HMAC tidak cocok atau payload rusak/dimanipulasi)
        # hasil berisi pesan error dari crypto.py
        jenis_serangan = "Data Tampering" if "HMAC Mismatch" in hasil else \
                         "Replay Attack" if "Replay" in hasil else "Data Corruption"
        
        # 3. Catat sebagai serangan!
        database.catat_log_serangan(jenis_serangan, hasil, status_integritas, crypto_info)
        
        return jsonify({
            "status": "rejected", 
            "pesan": "Akses Ditolak! Data terindikasi dimanipulasi.",
            "error_detail": hasil
        }), 403

# ==========================================
# ENDPOINT UNTUK WEB DASHBOARD
# ==========================================
@app.route('/')
def index():
    """Menampilkan halaman utama web (Frontend)."""
    return render_template('index.html')

@app.route('/api/data', methods=['GET'])
def api_data():
    """API untuk di-fetch oleh website setiap beberapa detik."""
    data_sensor = database.ambil_data_terbaru()
    return jsonify(data_sensor)

@app.route('/api/logs', methods=['GET'])
def api_logs():
    """API untuk mengambil log serangan di website."""
    log_serangan = database.ambil_log_serangan()
    return jsonify(log_serangan)

# ==========================================
# ENDPOINT STATISTIK PERFORMA
# ==========================================
@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Statistik performa kriptografi untuk dashboard."""
    stats = database.ambil_statistik()
    return jsonify(stats)

@app.route('/api/chart-data', methods=['GET'])
def api_chart_data():
    gabungan = database.ambil_data_chart_gabungan(30)
    return jsonify(gabungan)

# ==========================================
# ENDPOINT SIMULASI (Testing tanpa ESP32)
# ==========================================
@app.route('/api/simulate', methods=['POST'])
def simulate():
    """Simulasi pengiriman data sensor terenkripsi — untuk demo tanpa hardware."""
    suhu = round(random.uniform(25.0, 36.0), 2)
    kelembapan = round(random.uniform(60.0, 90.0), 2)
    
    # Enkripsi data sensor (seperti yang dilakukan ESP32)
    payload_base64, waktu_enkripsi, _ = crypto.enkripsi_data_sensor(suhu, kelembapan)
    
    # Proses melalui pipeline normal (dekripsi + verifikasi HMAC)
    sukses, hasil, waktu_dekripsi, status_integritas, crypto_info = crypto.proses_payload_esp32(payload_base64)
    
    if sukses:
        database.simpan_data_sensor(hasil['t'], hasil['h'], waktu_dekripsi, status_integritas, crypto_info)
        return jsonify({
            "status": "success",
            "suhu": hasil['t'],
            "kelembapan": hasil['h'],
            "waktu_enkripsi_ms": round(waktu_enkripsi, 2),
            "waktu_dekripsi_ms": round(waktu_dekripsi, 2)
        }), 200
    
    return jsonify({"status": "error", "detail": hasil}), 500

@app.route('/api/simulate-attack', methods=['POST'])
def simulate_attack():
    """Simulasi serangan tampering — membuktikan HMAC mendeteksi manipulasi."""
    suhu = round(random.uniform(25.0, 36.0), 2)
    kelembapan = round(random.uniform(60.0, 90.0), 2)
    
    # Buat payload terenkripsi yang valid
    payload_base64, _, _ = crypto.enkripsi_data_sensor(suhu, kelembapan)
    
    # TAMPER: ubah 1 byte di area ciphertext (simulasi man-in-the-middle)
    raw = b64.b64decode(payload_base64)
    tampered = bytearray(raw)
    tampered[20] = tampered[20] ^ 0xFF  # Flip satu byte
    payload_tampered = b64.b64encode(bytes(tampered)).decode('utf-8')
    
    # Proses payload yang sudah dimanipulasi
    sukses, hasil, waktu_ms, status_integritas, crypto_info = crypto.proses_payload_esp32(payload_tampered)
    
    if not sukses:
        database.catat_log_serangan("Data Tampering (Simulasi)", hasil, status_integritas, crypto_info)
        return jsonify({
            "status": "rejected",
            "pesan": "Serangan berhasil dideteksi! HMAC tidak cocok.",
            "detail": hasil
        }), 200
    
    return jsonify({"status": "error", "pesan": "Unexpected: data tampered diterima"}), 500

@app.route('/api/reset', methods=['POST'])
def reset_database():
    database.reset_semua_data()
    return jsonify({"status": "success", "pesan": "Database berhasil direset."}), 200

@app.route('/api/simulate-replay', methods=['POST'])
def simulate_replay():
    """Simulasi replay attack — membuktikan anti-replay window mendeteksi paket lama."""
    global _last_valid_payload
    
    suhu = round(random.uniform(25.0, 36.0), 2)
    kelembapan = round(random.uniform(60.0, 90.0), 2)
    
    # 1. Buat payload valid dulu (simpan sebagai referensi)
    _last_valid_payload, _, _ = crypto.enkripsi_data_sensor(suhu, kelembapan)
    
    # 2. Buat payload dengan timestamp dimundurkan 70 detik (melebihi window 60 detik)
    payload_backdated, _ = crypto.enkripsi_data_sensor_backdated(suhu, kelembapan, backdate_ms=70000)
    
    # 3. Kirim payload lama ke pipeline verifikasi
    sukses, hasil, waktu_ms, status_integritas, crypto_info = crypto.proses_payload_esp32(payload_backdated)
    
    if not sukses:
        database.catat_log_serangan("Replay Attack (Simulasi)", hasil, status_integritas, crypto_info)
        return jsonify({
            "status": "rejected",
            "pesan": "Replay attack berhasil dideteksi! Paket melebihi window 60 detik.",
            "detail": hasil
        }), 200
    
    return jsonify({"status": "error", "pesan": "Anti-replay gagal mendeteksi"}), 500

# ==========================================
# ENDPOINT EXPORT CSV (Gabungan)
# ==========================================
@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Export seluruh data sensor dan log serangan ke satu file CSV."""
    data_sensor = database.ambil_semua_data_sensor()
    log_serangan = database.ambil_semua_log_serangan()
    
    output = io.StringIO()
    # BOM agar Excel bisa baca UTF-8 dengan benar
    output.write('\ufeff')
    
    writer = csv.writer(output)
    
    # === Bagian 1: Data Sensor ===
    writer.writerow(['=== DATA SENSOR MIKROKLIMAT ==='])
    writer.writerow(['No', 'Timestamp', 'Suhu (°C)', 'Kelembapan (%RH)', 'Waktu Dekripsi (ms)', 'Status'])
    
    for i, row in enumerate(data_sensor, 1):
        writer.writerow([
            i,
            row['timestamp'],
            row['suhu'],
            row['kelembapan'],
            round(row['waktu_dekripsi_ms'], 4),
            row['status']
        ])
    
    # Pemisah
    writer.writerow([])
    
    # === Bagian 2: Log Serangan ===
    writer.writerow(['=== LOG SERANGAN / INSIDEN KEAMANAN ==='])
    writer.writerow(['No', 'Timestamp', 'Jenis Serangan', 'Detail', 'Status'])
    
    for i, log in enumerate(log_serangan, 1):
        writer.writerow([
            i,
            log['timestamp'],
            log['jenis_serangan'],
            log['detail'],
            log['status']
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    response.headers['Content-Disposition'] = 'attachment; filename=laporan_mikroklimat.csv'
    return response

# ==========================================
# AUTENTIKASI ADMIN
# ==========================================
def login_required(f):
    """Decorator — redirect ke login jika belum autentikasi."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET'])
def login_page():
    if session.get('admin_logged_in'):
        return redirect(url_for('db_viewer'))
    return render_template('login.html', error=None)

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if database.verifikasi_admin(username, password):
        session['admin_logged_in'] = True
        session['admin_username'] = username
        return redirect(url_for('db_viewer'))
    return render_template('login.html', error='Username atau password salah.')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ==========================================
# DB VIEWER (Dilindungi Login)
# ==========================================
@app.route('/db-viewer')
@login_required
def db_viewer():
    """Halaman viewer database mirip phpMyAdmin."""
    return render_template('db_viewer.html', username=session.get('admin_username'))

@app.route('/api/db-viewer/<table_name>', methods=['GET'])
@login_required
def api_db_viewer(table_name):
    """API untuk DB Viewer — ambil isi tabel dengan pagination."""
    ALLOWED_TABLES = ['sensor_data', 'attack_log', 'admin_users']
    if table_name not in ALLOWED_TABLES:
        return jsonify({"error": "Tabel tidak diizinkan"}), 403

    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    search = request.args.get('search', '').strip()
    offset = (page - 1) * per_page

    conn = sqlite3.connect(database.DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Kolom sensitif disembunyikan di tabel admin
    if table_name == 'admin_users':
        select_cols = "id, username, password_hash, created_at, last_login"
    else:
        select_cols = "*"

    # Ambil nama kolom
    cursor.execute(f"PRAGMA table_info({table_name})")
    all_cols = [row['name'] for row in cursor.fetchall()]
    # Kolom yang ditampilkan (sensor_data & attack_log tampil semua)
    display_cols = ['id','username','password_hash','created_at','last_login'] if table_name == 'admin_users' else all_cols

    # Query dengan search filter
    if search:
        conditions = " OR ".join([f"CAST({col} AS TEXT) LIKE ?" for col in display_cols])
        like_val = [f"%{search}%"] * len(display_cols)
        cursor.execute(f"SELECT COUNT(*) FROM (SELECT {select_cols} FROM {table_name}) WHERE {conditions}", like_val)
        total = cursor.fetchone()[0]
        cursor.execute(f"SELECT {select_cols} FROM {table_name} WHERE {conditions} ORDER BY id DESC LIMIT ? OFFSET ?",
                       like_val + [per_page, offset])
    else:
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        total = cursor.fetchone()[0]
        cursor.execute(f"SELECT {select_cols} FROM {table_name} ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, offset))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        "columns": display_cols,
        "rows": rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, -(-total // per_page))  # ceiling division
    })

@app.route('/api/db-viewer/admin/tambah', methods=['POST'])
@login_required
def admin_tambah():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({"status": "error", "pesan": "Username dan password wajib diisi."}), 400
    if len(password) < 6:
        return jsonify({"status": "error", "pesan": "Password minimal 6 karakter."}), 400
    ok = database.tambah_admin(username, password)
    if ok:
        return jsonify({"status": "success", "pesan": f"Admin '{username}' berhasil ditambahkan."})
    return jsonify({"status": "error", "pesan": "Username sudah digunakan."}), 409

@app.route('/api/db-viewer/admin/hapus/<int:admin_id>', methods=['DELETE'])
@login_required
def admin_hapus(admin_id):
    # Tidak bisa hapus diri sendiri
    cursor = sqlite3.connect(database.DB_NAME)
    row = cursor.execute("SELECT username FROM admin_users WHERE id=?", (admin_id,)).fetchone()
    cursor.close()
    if row and row[0] == session.get('admin_username'):
        return jsonify({"status": "error", "pesan": "Tidak bisa menghapus akun sendiri."}), 403
    ok, pesan = database.hapus_admin(admin_id)
    return jsonify({"status": "success" if ok else "error", "pesan": pesan})

if __name__ == '__main__':
    # Jalankan server di semua IP lokal pada port 5000
    # Sehingga ESP32 di jaringan WiFi yang sama bisa mengaksesnya
    app.run(host='0.0.0.0', port=5000, debug=True)