# CryptoSwing-PixelVault

AEAD (ChaCha20-Poly1305 / AES-GCM) tabanlı **görsel şifreleme** aracı. Anahtar, yüklediğiniz dosyadan **HKDF-SHA256** ile türetilir. Çıktı, `nonce + AAD + ciphertext(tag)` içeren ikili bir paket (`.bin`) olarak verilir.

## Özellikler
- 🔐 AEAD: **ChaCha20-Poly1305** veya **AES-GCM**
- 🧩 Anahtar türetimi: **HKDF(SHA-256)**
- 🖼️ PNG tabanlı sabit plaintext (deterministik paketleme için)
- 📦 Paket biçimi: `magic | alg | nonce | aad | ciphertext+tag` (binary)
- 🧪 Streamlit arayüzü ile yerel veya bulutta kullanım

## Kurulum (Yerel)
```bash
pip install -r requirements.txt
streamlit run cryptoswing_pixelvault_app.py
```

## Streamlit Cloud Dağıtım
1. Bu depoyu GitHub'a gönderin (push).
2. https://share.streamlit.io adresinden yeni uygulama oluşturun.
3. **Main file path**: `cryptoswing_pixelvault_app.py`
4. Dağıtın 🎉

## Güvenlik Notları
- Bu proje eğitim/demonstrasyon amaçlıdır.
- Üretim senaryolarında **nonce yönetimi**, **anahtar rotasyonu** ve **kimlik doğrulama politikaları** titizlikle ele alınmalıdır.
- AAD: `b"CHAOSIMG" || height || width || mode`

## Lisans
MIT
