import base64
import time
import json
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad, pad
import os

# Kunci statis (Pre-Shared Key) 32 byte untuk AES-256 dan HMAC
# Di skripsi, ini sudah dicatat sebagai batasan masalah (statis)
SECRET_KEY = b'KunciRahasiaSkripsiDepoArsip2026' # Panjang pas 32 karakter

def proses_payload_esp32(payload_base64):
    start_time = time.perf_counter()
    try:
        raw_data = base64.b64decode(payload_base64)
        if len(raw_data) < 64:
            raise ValueError("Payload terlalu pendek, terindikasi korup.")

        iv = raw_data[:16]
        tag_diterima = raw_data[-32:]
        ciphertext = raw_data[16:-32]

        iv_hex         = iv.hex()
        ciphertext_hex = ciphertext.hex()
        tag_hex        = tag_diterima.hex()

        hmac_obj = HMAC.new(SECRET_KEY, digestmod=SHA256)
        hmac_obj.update(iv + ciphertext)

        try:
            hmac_obj.verify(tag_diterima)
            status_integritas = "Terverifikasi"
        except ValueError:
            hmac_server = HMAC.new(SECRET_KEY, digestmod=SHA256)
            hmac_server.update(iv + ciphertext)
            hmac_dihitung_hex = hmac_server.digest().hex()

            waktu_proses_ms = (time.perf_counter() - start_time) * 1000
            crypto_info = {
                "iv_hex": iv_hex,
                "ciphertext_hex": ciphertext_hex,
                "hmac_tag_hex": tag_hex,
                "hmac_dihitung_hex": hmac_dihitung_hex,
                "payload_base64": payload_base64
            }
            return False, "HMAC Mismatch - Terindikasi Tampering/Manipulasi Data!", waktu_proses_ms, "Dicegah", crypto_info

        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        plaintext_padded = cipher.decrypt(ciphertext)
        plaintext_bytes  = unpad(plaintext_padded, AES.block_size)
        plaintext_str    = plaintext_bytes.decode('utf-8')
        data_json        = json.loads(plaintext_str)

        if 'ts' in data_json:
            ts_paket = data_json['ts']
            delta_ms = int(time.time() * 1000) - ts_paket
            if delta_ms < 0 or delta_ms > 60000:
                waktu_proses_ms = (time.perf_counter() - start_time) * 1000
                crypto_info = {
                    "iv_hex": iv_hex,
                    "ciphertext_hex": ciphertext_hex,
                    "hmac_tag_hex": tag_hex,
                    "payload_base64": payload_base64,
                    "plaintext_json": plaintext_str,
                    "delta_ms": delta_ms
                }
                return False, f"Replay Attack — delta {delta_ms}ms melebihi window 60000ms", waktu_proses_ms, "Dicegah", crypto_info

        waktu_proses_ms = (time.perf_counter() - start_time) * 1000
        crypto_info = {
            "iv_hex": iv_hex,
            "ciphertext_hex": ciphertext_hex,
            "hmac_tag_hex": tag_hex,
            "payload_base64": payload_base64,
            "plaintext_json": plaintext_str
        }
        return True, data_json, waktu_proses_ms, status_integritas, crypto_info

    except Exception as e:
        waktu_proses_ms = (time.perf_counter() - start_time) * 1000
        return False, f"Error: {str(e)}", waktu_proses_ms, "Dicegah", {}


def hitung_avalanche(plaintext_bytes, iv):
    """Menghitung avalanche effect dengan mengubah 1 bit pada plaintext."""
    padded1 = pad(plaintext_bytes, AES.block_size)
    cipher1 = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    ct1 = cipher1.encrypt(padded1)
    
    pt_mod = bytearray(plaintext_bytes)
    if len(pt_mod) > 0:
        pt_mod[0] ^= 0x01
    padded2 = pad(bytes(pt_mod), AES.block_size)
    cipher2 = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    ct2 = cipher2.encrypt(padded2)
    
    diff_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ct1, ct2))
    total_bits = len(ct1) * 8
    return (diff_bits / total_bits) * 100.0 if total_bits > 0 else 0.0

def enkripsi_data_sensor(suhu, kelembapan):
    """
    Enkripsi data sensor menjadi payload Base64.
    Format output setelah di-decode: IV (16 byte) + Ciphertext + HMAC (32 byte)
    Digunakan untuk simulasi pengujian tanpa ESP32.
    Mengembalikan: (payload_base64, waktu_enkripsi_ms)
    """
    start_time = time.perf_counter()

    # 1. Buat JSON plaintext (dengan timestamp untuk anti-replay)
    plaintext = json.dumps({
        "t": round(suhu, 2),
        "h": round(kelembapan, 2),
        "ts": int(time.time() * 1000)
    })
    plaintext_bytes = plaintext.encode('utf-8')

    # 2. Padding PKCS7 ke kelipatan 16 byte
    padded = pad(plaintext_bytes, AES.block_size)

    # 3. Generate random IV (16 byte)
    iv = os.urandom(16)

    # 4. Enkripsi AES-256-CBC
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)

    # 5. HMAC-SHA256 atas IV + Ciphertext (Encrypt-then-MAC)
    hmac_obj = HMAC.new(SECRET_KEY, digestmod=SHA256)
    hmac_obj.update(iv + ciphertext)
    tag = hmac_obj.digest()

    # 6. Gabung: IV + Ciphertext + HMAC Tag
    raw = iv + ciphertext + tag

    # 7. Hitung avalanche effect
    avalanche = hitung_avalanche(plaintext_bytes, iv)

    # 8. Encode Base64
    waktu_ms = (time.perf_counter() - start_time) * 1000
    return base64.b64encode(raw).decode('utf-8'), waktu_ms, avalanche


def enkripsi_data_sensor_backdated(suhu, kelembapan, backdate_ms=70000):
    """Enkripsi dengan timestamp yang sengaja dimundurkan untuk simulasi replay attack."""
    start_time = time.perf_counter()

    plaintext = json.dumps({
        "t": round(suhu, 2),
        "h": round(kelembapan, 2),
        "ts": int(time.time() * 1000) - backdate_ms
    })
    plaintext_bytes = plaintext.encode('utf-8')

    padded = pad(plaintext_bytes, AES.block_size)
    iv = os.urandom(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)

    hmac_obj = HMAC.new(SECRET_KEY, digestmod=SHA256)
    hmac_obj.update(iv + ciphertext)
    tag = hmac_obj.digest()

    raw = iv + ciphertext + tag
    waktu_ms = (time.perf_counter() - start_time) * 1000
    return base64.b64encode(raw).decode('utf-8'), waktu_ms