# CryptoSwing-PixelVault (Histogram Sürümü)

AEAD (ChaCha20-Poly1305 / AES-GCM) ile **ham piksel verisi** üzerinde şifreleme yapar, böylece **şifreli görüntü** görsel olarak gösterilebilir. Uygulama ayrıca **orijinal ve şifreli görüntü** için **histogram analizlerini** (R/G/B ve tüm kanallar) sunar.

## Özellikler
- 🔐 AEAD: **ChaCha20-Poly1305** veya **AES-GCM**
- 🧩 Anahtar türetimi: **HKDF(SHA-256)**
- 🖼️ Ham RGB piksel şifreleme → şifreli görüntü önizleme
- 📈 Histogramlar: R, G, B ve birleşik
- 📦 Güvenli paket: `magic | alg | nonce | aad | ciphertext||tag` (.bin)

## Çalıştırma
```bash
pip install -r requirements.txt
streamlit run cryptoswing_pixelvault_app.py
```

## Streamlit Cloud
- **Main file path:** `cryptoswing_pixelvault_app.py`
