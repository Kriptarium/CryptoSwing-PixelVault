
import streamlit as st
import io, os, struct
from PIL import Image
import numpy as np
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM

APP_NAME = "CryptoSwing-PixelVault"
MAGIC = b"CHAEADv1"

st.set_page_config(page_title=APP_NAME, page_icon="🧿", layout="wide")

# ---- Helpers ----
def read_key_bytes(file_bytes: bytes) -> bytes:
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

def package_ciphertext(alg_name: str, nonce: bytes, aad: bytes, ciphertext_plus_tag: bytes) -> bytes:
    pkg = bytearray()
    pkg += MAGIC
    pkg += bytes([len(alg_name)])
    pkg += alg_name.encode('ascii')
    pkg += bytes([len(nonce)])
    pkg += nonce
    pkg += struct.pack(">I", len(aad))
    pkg += aad
    pkg += struct.pack(">Q", len(ciphertext_plus_tag))
    pkg += ciphertext_plus_tag
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

def img_to_rgb_bytes(img: Image.Image) -> bytes:
    arr = np.array(img.convert("RGB"), dtype=np.uint8)
    return arr.tobytes(order="C")

def rgb_bytes_to_img(b: bytes, w: int, h: int) -> Image.Image:
    arr = np.frombuffer(b, dtype=np.uint8)
    if arr.size != w*h*3:
        raise ValueError("Boyut uyuşmazlığı: uzunluk H*W*3 değil.")
    arr = arr.reshape((h, w, 3))
    return Image.fromarray(arr, mode="RGB")

def compute_histograms(img: Image.Image):
    arr = np.array(img.convert("RGB"), dtype=np.uint8)
    r = arr[:,:,0].reshape(-1)
    g = arr[:,:,1].reshape(-1)
    b = arr[:,:,2].reshape(-1)
    r_hist = np.bincount(r, minlength=256)
    g_hist = np.bincount(g, minlength=256)
    b_hist = np.bincount(b, minlength=256)
    return r_hist, g_hist, b_hist

def plot_hist_colored(r_hist, g_hist, b_hist, title):
    fig, ax = plt.subplots()
    ax.plot(range(256), r_hist, label="R", color="red")
    ax.plot(range(256), g_hist, label="G", color="green")
    ax.plot(range(256), b_hist, label="B", color="blue")
    ax.set_title(title)
    ax.set_xlabel("Intensity (0–255)")
    ax.set_ylabel("Count")
    ax.legend()
    fig.tight_layout()
    return fig

# ---- Correlation utilities ----
def _horizontal_pairs(channel: np.ndarray):
    X = channel[:, :-1].reshape(-1)
    Y = channel[:, 1: ].reshape(-1)
    return X, Y

def _vertical_pairs(channel: np.ndarray):
    X = channel[:-1, :].reshape(-1)
    Y = channel[ 1:, :].reshape(-1)
    return X, Y

def _pearson_corr(x: np.ndarray, y: np.ndarray):
    if x.size == 0 or y.size == 0:
        return float('nan')
    return np.corrcoef(x, y)[0, 1]

def channel_correlations(img: Image.Image):
    A = np.array(img.convert("RGB"), dtype=np.uint8)
    R, G, B = A[:,:,0], A[:,:,1], A[:,:,2]
    res = {}
    for name, ch in [("R", R), ("G", G), ("B", B)]:
        xh, yh = _horizontal_pairs(ch)
        xv, yv = _vertical_pairs(ch)
        res[f"{name}_h"] = float(_pearson_corr(xh, yh))
        res[f"{name}_v"] = float(_pearson_corr(xv, yv))
    return res

def scatter_pairs_fig(channel: np.ndarray, title: str, max_pts=6000):
    x, y = _horizontal_pairs(channel)
    n = x.size
    if n > max_pts:
        idx = np.random.choice(n, size=max_pts, replace=False)
        x = x[idx]; y = y[idx]
    fig, ax = plt.subplots()
    ax.scatter(x, y, s=2)  # default color
    ax.set_title(title)
    ax.set_xlabel("Pixel i")
    ax.set_ylabel("Adjacent pixel")
    fig.tight_layout()
    return fig

# ---- Encryption over raw RGB ----
def encrypt_pixels(img: Image.Image, key_bytes: bytes, algorithm: str):
    img = img.convert("RGB")
    w, h = img.size
    mode = img.mode
    rgb_plain = img_to_rgb_bytes(img)

    aead_key = hkdf_sha256(key_bytes, info=b"AEAD-KEY-Chaos", length=32)
    aad = b"CHAOSIMG" + h.to_bytes(4,'big') + w.to_bytes(4,'big') + mode.encode('ascii')

    if algorithm == "ChaCha20-Poly1305":
        aead = ChaCha20Poly1305(aead_key); alg_name = "CHACHA20-POLY1305"
    else:
        aead = AESGCM(aead_key); alg_name = "AES-GCM"
    nonce = os.urandom(12)

    ct_plus_tag = aead.encrypt(nonce, rgb_plain, aad)  # len = len(plain)+16
    ct = ct_plus_tag[:-16]
    enc_img = rgb_bytes_to_img(ct, w, h)

    pkg = package_ciphertext(alg_name, nonce, aad, ct_plus_tag)
    return enc_img, pkg

def decrypt_pixels(pkg_bytes: bytes, key_bytes: bytes):
    alg_name, nonce, aad, ct_plus_tag = parse_package(pkg_bytes)
    aead_key = hkdf_sha256(key_bytes, info=b"AEAD-KEY-Chaos", length=32)
    if alg_name == "CHACHA20-POLY1305":
        aead = ChaCha20Poly1305(aead_key)
    elif alg_name == "AES-GCM":
        aead = AESGCM(aead_key)
    else:
        raise ValueError(f"Desteklenmeyen algoritma: {alg_name}")
    plain = aead.decrypt(nonce, ct_plus_tag, aad)  # raw RGB
    if not aad.startswith(b"CHAOSIMG"):
        raise ValueError("AAD beklenen formatta değil.")
    h = int.from_bytes(aad[8:12],"big")
    w = int.from_bytes(aad[12:16],"big")
    img = rgb_bytes_to_img(plain, w, h)
    return img, alg_name

# ---- UI ----
st.title("🧿 CryptoSwing-PixelVault")
st.caption("AEAD Görsel Şifreleme • ChaCha20-Poly1305 / AES-GCM • HKDF-SHA256 • R/G/B Histogram + Korelasyon + NPCR/UACI")

tab_enc, tab_dec = st.tabs(["🧪 Şifrele", "🔓 Çöz"])

with tab_enc:
    col_left, col_right = st.columns([1,1])
    with col_left:
        st.subheader("Görüntü ve Anahtar")
        img_file = st.file_uploader("Görüntü (PNG/JPG)", type=["png","jpg","jpeg","bmp","webp"], key="enc_img")
        key_file = st.file_uploader("Anahtar dosyası (örn. bit dizisi .txt)", type=None, key="enc_key")
        alg = st.selectbox("Algoritma", ["ChaCha20-Poly1305", "AES-GCM"])
        run = st.button("Şifrele ve Analiz Et")
    with col_right:
        st.info("Şifreleme ham piksel verisi üzerinde yapılır; böylece şifreli görüntü görsel olarak da gösterilebilir. Güvenli paket (.bin) ayrıca üretilir.")

    if run:
        if not img_file or not key_file:
            st.error("Lütfen hem görüntü hem anahtar dosyasını yükleyin.")
        else:
            try:
                key_bytes = read_key_bytes(key_file.read())
                orig_img = Image.open(io.BytesIO(img_file.read())).convert("RGB")
                enc_img, pkg = encrypt_pixels(orig_img, key_bytes, algorithm=alg)

                c1, c2 = st.columns([1,1])
                with c1:
                    st.subheader("Orijinal")
                    st.image(orig_img, use_column_width=True)
                with c2:
                    st.subheader("Şifreli Görüntü")
                    st.image(enc_img, use_column_width=True)

                # Histograms
                st.markdown("### Histogramlar — R/G/B")
                (r_o, g_o, b_o) = compute_histograms(orig_img)
                (r_e, g_e, b_e) = compute_histograms(enc_img)

                hc1, hc2 = st.columns([1,1])
                with hc1:
                    st.pyplot(plot_hist_colored(r_o, g_o, b_o, "Orijinal — R/G/B"))
                with hc2:
                    st.pyplot(plot_hist_colored(r_e, g_e, b_e, "Şifreli — R/G/B"))

                # Correlation numbers
                st.markdown("### Adjacent-Pixel Correlation (Pearson r) — yatay (h) / dikey (v)")
                corr_o = channel_correlations(orig_img)
                corr_e = channel_correlations(enc_img)
                colA, colB = st.columns([1,1])
                with colA:
                    st.write("**Orijinal**:")
                    st.json({k: round(v, 6) for k, v in corr_o.items()})
                with colB:
                    st.write("**Şifreli**:")
                    st.json({k: round(v, 6) for k, v in corr_e.items()})

                # Optional scatter plots: R channel samples
                st.markdown("#### Örnek saçılım grafiği (R kanalı, yatay komşular)")
                A = np.array(orig_img, dtype=np.uint8)[:,:,0]
                fig_o = scatter_pairs_fig(A, "Orijinal — R (komşu pikseller)")
                st.pyplot(fig_o)
                B = np.array(enc_img, dtype=np.uint8)[:,:,0]
                fig_e = scatter_pairs_fig(B, "Şifreli — R (komşu pikseller)")
                st.pyplot(fig_e)

                # NPCR & UACI
                st.markdown("### NPCR & UACI (Orijinal ↔ Şifreli)")
                def compute_npcr_uaci(img_a: Image.Image, img_b: Image.Image):
                    A = np.array(img_a.convert("RGB"), dtype=np.uint8)
                    B = np.array(img_b.convert("RGB"), dtype=np.uint8)
                    if A.shape != B.shape: raise ValueError("Boyutlar eşleşmiyor.")
                    H, W, C = A.shape
                    total = H*W
                    changed = np.any(A != B, axis=2)
                    npcr_over = changed.sum() / total * 100.0
                    diff = np.abs(A.astype(np.int16) - B.astype(np.int16))
                    uaci_over = diff.mean() / 255.0 * 100.0
                    npcr_r = (A[:,:,0] != B[:,:,0]).sum() / total * 100.0
                    npcr_g = (A[:,:,1] != B[:,:,1]).sum() / total * 100.0
                    npcr_b = (A[:,:,2] != B[:,:,2]).sum() / total * 100.0
                    uaci_r = (np.abs(A[:,:,0].astype(np.int16) - B[:,:,0].astype(np.int16)).mean()/255.0)*100.0
                    uaci_g = (np.abs(A[:,:,1].astype(np.int16) - B[:,:,1].astype(np.int16)).mean()/255.0)*100.0
                    uaci_b = (np.abs(A[:,:,2].astype(np.int16) - B[:,:,2].astype(np.int16)).mean()/255.0)*100.0
                    return {
                        "NPCR_overall_%": npcr_over, "UACI_overall_%": uaci_over,
                        "NPCR_R_%": npcr_r, "NPCR_G_%": npcr_g, "NPCR_B_%": npcr_b,
                        "UACI_R_%": uaci_r, "UACI_G_%": uaci_g, "UACI_B_%": uaci_b,
                    }
                metrics = compute_npcr_uaci(orig_img, enc_img)
                st.json({k: (round(v, 6) if isinstance(v, float) else v) for k,v in metrics.items()})

                st.download_button("⬇️ Şifreli Paketi İndir (.bin)", data=pkg, file_name="pixelvault_encrypted.bin")

            except Exception as e:
                st.exception(e)

with tab_dec:
    st.subheader("Şifreli Paketi Çöz ve Analiz Et")
    pkg_file = st.file_uploader("Şifreli paket (.bin)", type=["bin"], key="dec_pkg")
    key_file2 = st.file_uploader("Anahtar dosyası (aynısı)", type=None, key="dec_key")
    if st.button("Çöz ve Analiz Et"):
        if not pkg_file or not key_file2:
            st.error("Lütfen hem şifreli paket hem anahtar dosyasını yükleyin.")
        else:
            try:
                pkg_bytes = pkg_file.read()
                key_bytes2 = read_key_bytes(key_file2.read())
                dec_img, alg_name = decrypt_pixels(pkg_bytes, key_bytes2)
                st.success(f"Doğrulama OK • Algoritma: {alg_name}")

                st.image(dec_img, caption="Çözülen Görüntü", use_column_width=True)

                # Correlations for decrypted
                corr_d = channel_correlations(dec_img)
                st.markdown("### Korelasyon (Çözülen) — yatay/dikey")
                st.json({k: round(v, 6) for k, v in corr_d.items()})

                # Histograms for decrypted
                r_d, g_d, b_d = compute_histograms(dec_img)
                st.pyplot(plot_hist_colored(r_d, g_d, b_d, "Decrypted — R/G/B"))

                buf = io.BytesIO()
                dec_img.save(buf, format="PNG")
                st.download_button("⬇️ PNG Olarak İndir", data=buf.getvalue(), file_name="pixelvault_decrypted.png")

            except Exception as e:
                st.exception(e)
