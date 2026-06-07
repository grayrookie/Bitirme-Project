# 🛡️ Cyber Sentinel - Siber Güvenlik Kontrol Merkezi

Cyber Sentinel, yerel ağ analizleri, port tarama, zafiyet analizi ve tehdit istihbaratı gibi siber güvenlik işlemlerini gerçekleştiren modern, kullanıcı dostu ve premium tasarımlı bir masaüstü uygulamasıdır.

Bu uygulama hem web tarayıcısı üzerinden kullanılabilen bir **Flask (Python) backend** sunucusuna hem de masaüstü uygulaması olarak çalışabilen **Electron** entegrasyonuna sahiptir.

---

## 🚀 Temel Özellikler

- **Ağ Keşfi (Ping - ICMP):** Hedef IP/Domain adresinin aktiflik durumunu sorgular.
- **Port Tarayıcı:** En sık kullanılan portları tarayarak açık servisleri raporlar.
- **Derin Port Analizi (Banner Grabber):** Servislerin sürüm bilgilerini ve işletim sistemlerini tespit eder (Nmap / Soket tabanlı).
- **Web Sunucu Yük & DoS Stres Testi:** Yerel test sunucularınızın yük taşıma kapasitesini asenkron HTTP istekleri ile ölçer ve gecikme grafiğini çizer.
- **Veri Sızıntısı Kontrolü (Breach Checker):** E-posta adreslerinin geçmiş sızıntılarda yer alıp almadığını kontrol eder.
- **Güvenli Link & Dosya Analizi:** VirusTotal entegrasyonu ile dosya ve URL taramaları yapar.
- **Statik Kod Analizi (SAST):** Kaynak kodlardaki olası zafiyetleri (eval, os.system vb.) tarar.
- **Yapay Zeka Tiyaj Desteği:** Google Gemini API entegrasyonu ile tarama sonuçlarını ve kod zafiyetlerini analiz ederek çözüm önerileri sunar.

---

## 🛠️ Kurulum ve Çalıştırma

### 1. Gereksinimler
Uygulamayı çalıştırabilmek için bilgisayarınızda **Python 3.8+** ve **Node.js** yüklü olmalıdır.

### 2. Python Kütüphanelerinin Kurulumu
Proje ana dizininde bir terminal açarak gerekli Python paketlerini yükleyin:
```bash
pip install -r requirements.txt
```

### 3. Node.js Paketlerinin Kurulumu (Electron için)
Masaüstü arayüzünü çalıştırmak üzere gerekli NPM paketlerini kurun:
```bash
npm install
```

### 4. API Anahtarlarının Yapılandırılması
Ana dizindeki `.env.example` dosyasının bir kopyasını oluşturup adını `.env` yapın. Ardından gerekli API anahtarlarını girin:
- `GEMINI_API_KEY`: Yapay zeka analizi için Google Gemini anahtarı.
- `VIRUSTOTAL_API_KEY`: Güvenli link ve dosya taramaları için VirusTotal anahtarı.

---

## 🖥️ Çalıştırma Talimatları

### Web Arayüzü Olarak Çalıştırma
Sadece web sunucusunu başlatmak ve tarayıcıdan erişmek için:
```bash
python run_web.py
```
Sunucu başlatıldıktan sonra tarayıcınızdan `http://127.0.0.1:5000` adresine gidebilirsiniz.

### Masaüstü Uygulaması (Electron) Olarak Çalıştırma
Masaüstü penceresi ile birlikte çalıştırmak için:
```bash
npm start
```

---

## 📄 Lisans
Bu proje eğitim ve kişisel defansif test amaçlarıyla geliştirilmiştir. Yetkisiz sistemlere karşı yapılan taramalar veya yük testleri yasal sorumluluk doğurabilir.
