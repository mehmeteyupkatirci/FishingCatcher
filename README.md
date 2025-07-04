﻿# FishingCatcher
# 🛡️ Phishing URL Checker

Bu C# konsol uygulaması, kullanıcı tarafından girilen URL'lerin zararlı (phishing/malware) olup olmadığını çeşitli kaynaklardan kontrol ederek değerlendirir. Uygulama, hem çevrimiçi API'leri hem de yerel bir CSV veri kümesini kullanarak tehditleri tespit eder.

---

## 🚀 Özellikler

- ✅ **Yerel CSV verisi** ile hızlı URL eşleşme (örneğin: `phish_score.csv`, `custom_found.csv`)
- 🧠 **Heuristik analiz** (şüpheli kelimeler, IP adresi kullanımı, uzunluk, tire analizi)
- 🌐 **Google Safe Browsing API** üzerinden zararlı URL kontrolü
- 🧪 **VirusTotal API** ile çoklu motorlara dayalı zararlı URL analizi
- 🧾 **custom_found.csv** üzerinden kendi veritabanını geliştirme (VirusTotal'dan zararlı dönen her URL eklenir)
- 🖍️ **Renkli terminal çıktısı** ve 🧮 **risk skoru değerlendirmesi**

---

## 🛠️ Kurulum

1. Bu repository'i klonla:
   ```bash
   git clone https://github.com/kullanici-adi/proje-adi.git
   cd proje-adi
