# CryptoSwing-PixelVault (R/G/B renkli histogram + NPCR/UACI)

Ham RGB piksel verisi üzerinde AEAD (ChaCha20-Poly1305 / AES-GCM) ile şifreleme yapar; **şifreli görüntüyü görsel olarak gösterir** ve **R/G/B renkli histogramlar** ile **NPCR/UACI** metriklerini raporlar.

## Özellikler
- 🔐 AEAD: ChaCha20-Poly1305 veya AES-GCM
- 🧩 HKDF(SHA-256) ile anahtar türetimi
- 🖼️ Ham RGB şifreleme → şifreli görüntü önizleme
- 🎨 Histogramlar: R (kırmızı), G (yeşil), B (mavi)
- 📊 Metrikler: **NPCR** (Number of Pixels Change Rate) ve **UACI** (Unified Average Changing Intensity)

## Çalıştırma
```bash
pip install -r requirements.txt
streamlit run cryptoswing_pixelvault_app.py
```

## Streamlit Cloud
- **Main file path:** `cryptoswing_pixelvault_app.py`
