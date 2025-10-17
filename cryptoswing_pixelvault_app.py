
import streamlit as st
import io, os, struct
from PIL import Image
import numpy as np

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM

APP_NAME = "CryptoSwing-PixelVault"
MAGIC = b"CHAEADv1"

st.set_page_config(page_title=APP_NAME, page_icon="🧿", layout="centered")

# --- Helpers ---
def read_key_bytes(file_bytes: bytes) -> bytes:
    # If the key file looks like only '0'/'1', parse bits. Otherwise, use raw bytes.
    try:
        txt = file_bytes.decode('utf-8', errors='ignore').strip()
    except:
        txt = None
    if txt and set(txt) <= set("01 \n\r\t") and len(txt.replace(" ","").replace("\n","")) >= 8:
        bits = "".join(ch for ch in txt if ch in "01")
        if len(bits) % 8 != 0:
            bits += "0" * (8 - len(bits) % 8)
        out = bytearray()
        for i in range(0, len(bits), 8):
            out.append(int(bits[i:i+8], 2))
        return bytes(out)
    return file_bytes

def hkdf_sha256(ikm: bytes, info: bytes, length: int, salt: bytes=b"ChaosImgSalt"):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)

def package_ciphertext(alg_name: str, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    pkg = bytearray()
    pkg += MAGIC
    pkg += bytes([len(alg_name)])
    pkg += alg_name.encode('ascii')
    pkg += bytes([len(nonce)])
    pkg += nonce
    pkg += struct.pack(">I", len(aad))
    pkg += aad
    pkg += struct.pack(">Q", len(ciphertext))
    pkg += ciphertext
    return bytes(pkg)

def parse_package(data: bytes):
    off = 0
    if data[:8] != MAGIC:
        raise ValueError("Geçersiz dosya: MAGIC eşleşmedi.")
    off += 8
    alg_len = data[off]; off += 1
    alg_name = data[off:off+alg_len].decode("ascii"); off += alg_len
    nonce_len = data[off]; off += 1
    nonce = data[off:off+nonce_len]; off += nonce_len
    aad_len = struct.unpack(">I", data[off:off+4])[0]; off += 4
    aad = data[off:off+aad_len]; off += aad_len
    ct_len = struct.unpack(">Q", data[off:off+8])[0]; off += 8
    ct = data[off:off+ct_len]; off += ct_len
    return alg_name, nonce, aad, ct

def encrypt_image(img_bytes: bytes, key_bytes: bytes, algorithm: str):
    # Load and re-encode as PNG for deterministic bytes
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    w, h = img.size
    mode = img.mode
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    plaintext = buf.getvalue()

    aead_key = hkdf_sha256(key_bytes, info=b"AEAD-KEY-Chaos", length=32)

    if algorithm == "ChaCha20-Poly1305":
        aead = ChaCha20Poly1305(aead_key)
        nonce = os.urandom(12)
        alg_name = "CHACHA20-POLY1305"
    else:
        aead = AESGCM(aead_key)
        nonce = os.urandom(12)
        alg_name = "AES-GCM"

    aad = b"CHAOSIMG" + h.to_bytes(4,'big') + w.to_bytes(4,'big') + mode.encode('ascii')
    ciphertext = aead.encrypt(nonce, plaintext, aad)

    pkg = package_ciphertext(alg_name, nonce, aad, ciphertext)
    return pkg, img  # return original PIL for preview

def decrypt_package(pkg_bytes: bytes, key_bytes: bytes):
    alg_name, nonce, aad, ct = parse_package(pkg_bytes)
    aead_key = hkdf_sha256(key_bytes, info=b"AEAD-KEY-Chaos", length=32)
    if alg_name == "CHACHA20-POLY1305":
        aead = ChaCha20Poly1305(aead_key)
    elif alg_name == "AES-GCM":
        aead = AESGCM(aead_key)
    else:
        raise ValueError(f"Desteklenmeyen algoritma: {alg_name}")
    plaintext = aead.decrypt(nonce, ct, aad)
    img = Image.open(io.BytesIO(plaintext)).convert("RGB")
    return img, alg_name, aad

# --- UI ---
st.title("🧿 CryptoSwing-PixelVault")
st.caption("AEAD ile Görsel Şifreleme • ChaCha20-Poly1305 / AES-GCM • HKDF-SHA256 anahtar türetimi")

with st.sidebar:
    st.header("Hakkında")
    st.markdown("""
**CryptoSwing-PixelVault**, görselleri AEAD (kimlik doğrulamalı şifreleme) ile güvenle paketler:
- Algoritmalar: **ChaCha20-Poly1305** veya **AES-GCM**
- Anahtar: Yüklediğiniz dosyadan **HKDF(SHA-256)** ile türetilir
- Paket: `magic | alg | nonce | aad | ciphertext+tag` (ikili .bin)
 """)
    st.markdown("---")
    st.write("⚠️ Bu uygulama örnek/demo amaçlıdır. Üretim ortamında anahtar yönetimi ve nonce politikaları dikkatle tasarlanmalıdır.")

tab_enc, tab_dec = st.tabs(["🧪 Şifrele", "🔓 Çöz"])

with tab_enc:
    st.subheader("Görüntü Şifrele")
    img_file = st.file_uploader("Görüntü (PNG/JPG)", type=["png","jpg","jpeg","bmp","webp"], key="enc_img")
    key_file = st.file_uploader("Anahtar dosyası (örn. bit dizisi içeren .txt)", type=None, key="enc_key")
    alg = st.selectbox("Algoritma", ["ChaCha20-Poly1305", "AES-GCM"])
    if st.button("Şifrele"):
        if not img_file or not key_file:
            st.error("Lütfen hem görüntü hem anahtar dosyasını yükleyin.")
        else:
            try:
                key_bytes = read_key_bytes(key_file.read())
                pkg, preview_img = encrypt_image(img_file.read(), key_bytes, algorithm=alg)
                st.success("Şifreleme başarılı!")
                st.image(preview_img, caption="Önizleme (PNG tabanı)", use_column_width=True)
                st.download_button("⬇️ Şifreli Paketi İndir (.bin)", data=pkg, file_name="pixelvault_encrypted.bin")
                st.info(f"Paket boyutu: {len(pkg):,} bayt")
            except Exception as e:
                st.exception(e)

with tab_dec:
    st.subheader("Şifreli Paketi Çöz")
    pkg_file = st.file_uploader("Şifreli paket (.bin)", type=["bin"], key="dec_pkg")
    key_file2 = st.file_uploader("Anahtar dosyası (aynısı)", type=None, key="dec_key")
    if st.button("Çöz"):
        if not pkg_file or not key_file2:
            st.error("Lütfen hem şifreli paket hem anahtar dosyasını yükleyin.")
        else:
            try:
                pkg_bytes = pkg_file.read()
                key_bytes2 = read_key_bytes(key_file2.read())
                img, alg_name, aad = decrypt_package(pkg_bytes, key_bytes2)
                st.success(f"Doğrulama OK • Algoritma: {alg_name}")
                st.image(img, caption="Çözülen Görüntü", use_column_width=True)

                buf = io.BytesIO()
                img.save(buf, format="PNG")
                png_bytes = buf.getvalue()
                st.download_button("⬇️ PNG Olarak İndir", data=png_bytes, file_name="pixelvault_decrypted.png")
                st.caption(f"PNG boyutu: {len(png_bytes):,} bayt")
            except Exception as e:
                st.exception(e)
