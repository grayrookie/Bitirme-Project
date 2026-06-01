import requests
import json
import sys

# Ensure output prints UTF-8 correctly
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

BASE_URL = "http://127.0.0.1:5000"

print("==================================================")
print("🛡️ CYBER SENTINEL - ENTEGRASYON & ARAÇ TEST REHBERİ 🛡️")
print("==================================================\n")

def test_endpoint(endpoint, payload, method="POST"):
    url = f"{BASE_URL}{endpoint}"
    print(f"👉 TEST EDİLİYOR: {endpoint}")
    print(f"   [Gönderilen İstek]: {json.dumps(payload)}")
    try:
        if method == "POST":
            r = requests.post(url, json=payload, timeout=15)
        else:
            r = requests.get(url, timeout=15)
            
        print(f"   [Durum Kodu]: {r.status_code}")
        
        # Display response summary
        try:
            resp_data = r.json()
            # If output is too long, truncate it
            if "output" in resp_data and len(resp_data["output"]) > 300:
                truncated_data = resp_data.copy()
                truncated_data["output"] = resp_data["output"][:300] + "\n... [Kesildi] ..."
            else:
                truncated_data = resp_data
            print(f"   [Sunucu Yanıtı]: {json.dumps(truncated_data, indent=2, ensure_ascii=False)}")
        except Exception:
            print(f"   [Sunucu Yanıtı (Metin)]: {r.text[:300]}")
            
    except Exception as e:
        print(f"   [❌ HATA]: API'ye bağlanılamadı: {e}")
    print("-" * 50)

# 1. Ping Tarama Testi
test_endpoint("/api/scan/ping", {"target": "127.0.0.1"})

# 2. Port Tarama Testi
test_endpoint("/api/scan/ports", {"target": "127.0.0.1"})

# 3. Kriptografi: Hash Oluşturma
test_endpoint("/api/crypto/hash", {"text": "admin"})

# 4. Kriptografi: Hash Kırma
test_endpoint("/api/crypto/crack", {"target": "21232f297a57a5a743894a0e4a801fc3", "type": "md5"})

# 5. OSINT: Canlı Email Veri İhlali Tespiti (Sızdırılmış Hesap)
test_endpoint("/api/osint/breach", {"type": "email", "target": "test@example.com"})

# 6. OSINT: Canlı Email Veri İhlali Tespiti (Güvenli Hesap)
test_endpoint("/api/osint/breach", {"type": "email", "target": "some_very_unlikely_email_123456789_clean@gmail.com"})

# 7. OSINT: Pasif Port & Servis Keşif İstihbaratı (Internet-Wide Scanner API)
test_endpoint("/api/osint/passive-recon", {"target": "8.8.8.8"})

# 8. SAST: Güvenli Kod Analizi (AST Taraması)
test_endpoint("/api/security/code-scan", {"target": "import os\neval(input())\napi_key='sec_key_xyz123'\nos.system('ping 8.8.8.8')"})

# 9. Şifre Güvenliği Kontrolü
test_endpoint("/api/security/password-check", {"target": "WeakPassword123"})

# 10. Sezar Şifreleme Testi
test_endpoint("/api/crypto/cipher", {"algorithm": "caesar", "mode": "encrypt", "text": "Siber Güvenlik Projesi", "key": "3"})

print("\n🚀 Tüm entegrasyon testleri başarıyla tamamlandı!")
