# Implementasi Caesar Cipher di Python
def caesar_encrypt(plaintext, shift):
    result = ""
    for char in plaintext:
        if char.isalpha():  # hanya huruf
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char  # spasi atau karakter lain tidak diubah
    return result
def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

#TUGAS 2 - Kriptografi K-01
# ==============================
# IDENTITAS MAHASISWA
# ==============================
print("====================================")
print("NPM           : 237064416051")  
print("Nama Lengkap  : ALEXIUS GRENALDI HASIOLAN SIHOMBING")  
print("Mata Kuliah   : Kriptografi")
print("Kelas         : K-01")      
print("Program Studi : Teknik Informatika")
print("====================================\n")

# Contoh penggunaan
plaintext = "SELAMAT PAGI"
shift = 3
# Enkripsi
ciphertext = caesar_encrypt(plaintext, shift)
print("Plaintext :", plaintext)
print("Ciphertext:", ciphertext)
# Dekripsi
decrypted = caesar_decrypt(ciphertext, shift)
print("Dekripsi  :", decrypted)


# Caesar Cipher - Versi Interaktif
def caesar_encrypt(plaintext, shift):
    result = ""
    for char in plaintext:
        if char.isalpha():  # hanya huruf
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char  # karakter selain huruf tidak diubah
    return result
def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)


# Program utama
print("=== Caesar Cipher ===")
plaintext = input("Masukkan plaintext: ")
shift = int(input("Masukkan nilai kunci (shift): "))
# Enkripsi
ciphertext = caesar_encrypt(plaintext, shift)
print("\nHasil Enkripsi :", ciphertext)
# Dekripsi
decrypted = caesar_decrypt(ciphertext, shift)
print("Hasil Dekripsi :", decrypted)



# 02 Model Komunikasi Kriptografi
"""
Contoh implementasi kriptografi:- Kriptografi simetris: AES (CBC + PKCS7 padding)- Kriptografi asimetris: RSA (PKCS1_OAEP)- Skema hibrida: AES untuk pesan + RSA untuk mengenkripsi kunci AES
Penulis: Bapak Dr. Arie Gunawan, S.Kom., MMSI.
Tanggal: 11 April 2026
"""
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64


# ----------------------------
# 1) Fungsi kriptografi simetris (AES)
# ----------------------------
def generate_aes_key(key_size_bits=256):
    """Generate AES key (in bytes). key_size_bits = 128, 192, or 256."""
    return get_random_bytes(key_size_bits // 8)

def aes_encrypt(plaintext: bytes, key: bytes):
    """
    Encrypt plaintext (bytes) using AES-CBC with PKCS7 padding.
    Returns tuple (iv, ciphertext) in bytes.
    """

    iv = get_random_bytes(16)  # AES block size = 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))

    return iv, ct


#Koding (Lanjutan):
def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes):
    """Decrypt AES-CBC ciphertext and return plaintext bytes."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    pt_padded = cipher.decrypt(ciphertext)
    pt = unpad(pt_padded, AES.block_size)
    return pt
# ----------------------------
# 2) Fungsi kriptografi asimetris (RSA)
# ----------------------------
def generate_rsa_keypair(key_size=2048):
    """Generate RSA key pair. Returns (private_key_obj, public_key_obj)."""
    key = RSA.generate(key_size)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


#Koding (Lanjutan):
def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes):
    """Decrypt AES-CBC ciphertext and return plaintext bytes."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ciphertext)
    pt = unpad(pt_padded, AES.block_size)
    return pt
# ----------------------------
# 2) Fungsi kriptografi asimetris (RSA)
# ----------------------------
def generate_rsa_keypair(key_size=2048):
    """Generate RSA key pair. Returns (private_key_obj, public_key_obj)."""
    key = RSA.generate(key_size)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# Koding (Lanjutan):
def rsa_encrypt(message: bytes, public_key: RSA.RsaKey):
    """Encrypt message bytes with RSA public key using OAEP."""
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(message)
def rsa_decrypt(ciphertext: bytes, private_key: RSA.RsaKey):
    """Decrypt RSA-OAEP ciphertext with RSA private key."""
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext)


# Koding (Lanjutan):
# ----------------------------
# 3) Contoh: skema hibrida (praktis di dunia nyata)
# ----------------------------
def hybrid_encrypt(plaintext: bytes, rsa_public_key: RSA.RsaKey):
    """
    1. Generate random AES key
    2. Encrypt plaintext with AES
    3. Encrypt AES key with RSA public key
    Returns dict with base64-encoded fields for convenience.
    """
    
    aes_key = generate_aes_key(256)
    iv, ct = aes_encrypt(plaintext, aes_key)
    enc_aes_key = rsa_encrypt(aes_key, rsa_public_key)
    return {
        "enc_aes_key_b64": base64.b64encode(enc_aes_key).decode('ascii'),
        "iv_b64": base64.b64encode(iv).decode('ascii'),
        "ciphertext_b64": base64.b64encode(ct).decode('ascii')
    }

#Koding (Lanjutan):
def hybrid_decrypt(payload: dict, rsa_private_key: RSA.RsaKey):
    """
    1. Decrypt AES key using RSA private key
    2. Decrypt ciphertext using AES key and IV
    payload expects base64-encoded strings: enc_aes_key_b64, iv_b64, ciphertext_b64
    """
    
    enc_aes_key = base64.b64decode(payload["enc_aes_key_b64"])
    iv = base64.b64decode(payload["iv_b64"])
    ct = base64.b64decode(payload["ciphertext_b64"])
    aes_key = rsa_decrypt(enc_aes_key, rsa_private_key)
    plaintext = aes_decrypt(iv, ct, aes_key)
    return plaintext

# ----------------------------
# 4) Demonstrasi singkat (run ketika file dijalankan)
# ----------------------------
# Pesan contoh (plaintext)
if __name__ == "__main__":
    # Pesan contoh
    pesan = "Halo, ini contoh pesan rahasia untuk mahasiswa.".encode('utf-8')

    # AES
    print("=== Demonstrasi Kriptografi Simetris (AES) ===")
    key_aes = generate_aes_key(256)
    iv, ct = aes_encrypt(pesan, key_aes)
    print("AES Key (base64):", base64.b64encode(key_aes).decode())
    print("IV (base64):", base64.b64encode(iv).decode())
    print("Ciphertext (base64):", base64.b64encode(ct).decode())

    pt = aes_decrypt(iv, ct, key_aes)
    print("Hasil dekripsi AES:", pt.decode('utf-8'))

    # RSA
    print("\n=== Demonstrasi Kriptografi Asimetris (RSA) ===")
    priv, pub = generate_rsa_keypair(2048)

    sample = b"Ini pesan kecil"
    ct_rsa = rsa_encrypt(sample, pub)
    print("Ciphertext RSA (base64):", base64.b64encode(ct_rsa).decode())

    pt_rsa = rsa_decrypt(ct_rsa, priv)
    print("Hasil dekripsi RSA:", pt_rsa.decode())

    # Hybrid
    print("\n=== Demonstrasi Skema Hibrida (RSA + AES) ===")
    hybrid = hybrid_encrypt(pesan, pub)

    print("Payload hybrid (ringkas):")
    print(" enc_aes_key_b64:", hybrid["enc_aes_key_b64"][:60], "...")
    print(" iv_b64        :", hybrid["iv_b64"])
    print(" ciphertext_b64:", hybrid["ciphertext_b64"][:60], "...")

    recovered = hybrid_decrypt(hybrid, priv)
    print("Hasil dekripsi hybrid:", recovered.decode('utf-8'))
