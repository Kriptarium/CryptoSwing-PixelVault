# CryptoSwing-PixelVault (Correlation-enabled)

Bu sürüm, AEAD (ChaCha20-Poly1305 / AES-GCM) ile ham RGB şifreleme yapar ve:
- R/G/B **renkli histogramlar**
- **Adjacent-pixel correlation** (yatay ve dikey) — sayısal ve örnek scatter
- **NPCR/UACI** metrikleri
hesaplar.

## Çalıştırma
```bash
pip install -r requirements.txt
streamlit run cryptoswing_pixelvault_app.py
```

## Streamlit Cloud
- **Main file path:** `cryptoswing_pixelvault_app.py`
