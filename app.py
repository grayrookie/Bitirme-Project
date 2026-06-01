import socket
import subprocess
import platform
import concurrent.futures
import requests
import hashlib
import os
import sys
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify

# Dynamic path resolution for PyInstaller standalone build
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

from dotenv import load_dotenv
# .env dosyasını güvenli bir şekilde sunucu hafızasına yükler
load_dotenv(dotenv_path=os.path.join(base_path, ".env"))

app = Flask(__name__,
            template_folder=os.path.join(base_path, "templates"),
            static_folder=os.path.join(base_path, "static"))

# API Keys Configuration (Yönetici buraya kendi anahtarlarını yazabilir veya .env dosyasını kullanabilir)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

def clean_target_domain(target):
    if not target:
        return ""
    target = target.strip()
    # Add http:// if scheme not specified so urlparse can correctly extract netloc
    if not target.lower().startswith(("http://", "https://")):
        parsed = urlparse("http://" + target)
    else:
        parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    # Split by / and : to get the clean domain name (netloc) without paths or ports
    domain = domain.split("/")[0].split(":")[0]
    return domain

# Common ports to scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy"
}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan/ping", methods=["POST"])
def ping_scan():
    """Pings a target to see if it's alive."""
    data = request.json
    target_raw = data.get("target")

    if not target_raw:
        return jsonify({"error": "Hedef IP belirtilmedi"}), 400

    target = clean_target_domain(target_raw)

    # Ping command parameters
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
    
    # Send 2 packets because the first one might get lost during ARP resolution
    command = ['ping', param, '2', timeout_param, timeout_val, target]

    try:
        # Use shell=True for windows to ensure it correctly finds the ping executable
        use_shell = platform.system().lower() == 'windows'
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=use_shell)
        
        # Check output for standard "TTL=" which means a successful Echo Reply was received
        output = response.stdout.decode('utf-8', errors='ignore').lower()
        is_alive = response.returncode == 0 and "ttl=" in output
        
        return jsonify({"target": target, "alive": is_alive, "output": output[:200]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def scan_single_port(target, port):
    """Attempt to connect to a specific port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) # Short timeout
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result == 0:
            return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "status": "open"}
    except:
        pass
    return None

@app.route("/api/scan/ports", methods=["POST"])
def port_scan():
    """Scans common TCP ports on a target."""
    data = request.json
    target_raw = data.get("target")
    
    if not target_raw:
        return jsonify({"error": "Hedef belirtilmedi."}), 400

    target = clean_target_domain(target_raw)

    # Resolve hostname to IP if needed
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return jsonify({"error": "Hata: Hedef alan adı çözümlenemedi (DNS Hatası). Lütfen girdiğiniz hedef adresi kontrol edin."}), 400

    open_ports = []
    
    # Use ThreadPoolExecutor for fast scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_single_port, target_ip, port): port for port in COMMON_PORTS.keys()}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                
    # Sort open ports by port number
    open_ports = sorted(open_ports, key=lambda x: x["port"])
    
    return jsonify({
        "target": target,
        "target_ip": target_ip,
        "open_ports": open_ports
    })

@app.route("/api/scan/banner", methods=["POST"])
def banner_grab():
    target_raw = request.json.get("target")
    port_val = request.json.get("port")
    
    if not target_raw:
        return jsonify({"error": "Hedef belirtilmedi."}), 400
        
    target = clean_target_domain(target_raw)
    
    # Port validation and default value
    if not port_val or str(port_val).strip() == "":
        port = 80
    else:
        try:
            port = int(port_val)
        except ValueError:
            port = 80
            
    if port < 1 or port > 65535:
        return jsonify({"error": "Hata: Geçersiz Port Numarası! Port değeri 1-65535 arasında olmalıdır."}), 400

    # HTTP/Web portları: HEAD isteği gönder, sunucu yanıtını oku
    HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888}

    # Hedefin lokal mi harici mi olduğunu belirle
    LOCAL_TARGETS = {"127.0.0.1", "localhost", "::1"}
    is_local = target.lower() in LOCAL_TARGETS
    # Lokal hedeflerde 3s, harici (internet) hedeflerde 2s timeout
    connect_timeout = 3.0 if is_local else 2.0
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(connect_timeout)
        sock.connect((target, port))
        
        banner = ""
        
        if port in HTTP_PORTS:
            # Web portları: standart HTTP HEAD isteği gönder
            try:
                http_req = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                sock.send(http_req.encode())
                banner = sock.recv(2048).decode(errors='ignore').strip()
            except socket.timeout:
                pass
        else:
            # SSH (22), FTP (21), SMTP (25), POP3 (110), IMAP (143), Telnet (23) vb.
            # Bu servisler bağlantı kurulunca kendi banner'larını otomatik gönderir.
            # Biz hiçbir şey GÖNDERMEDEN sadece dinleriz.
            try:
                banner = sock.recv(1024).decode(errors='ignore').strip()
            except socket.timeout:
                pass
        
        sock.close()
        
        if not banner:
            return jsonify({"port": port, "banner": "Port açık ve bağlantı kuruldu, ancak servis herhangi bir banner göndermedi (gizli servis veya sessiz protokol)."})
        
        return jsonify({"port": port, "banner": banner})
    
    except socket.timeout:
        # Harici hedeflerde timeout → Firewall/IDS/IPS analiz mesajı
        if not is_local:
            firewall_msg = (
                f"[!] DURUM: Port {port} Açık/Filtreli olabilir ancak sunucu el sıkışma isteğine (TCP Handshake) yanıt vermedi.\n\n"
                f"[🛡️ Analiz]: Hedef sistem kurumsal bir Güvenlik Duvarı (Firewall/IDS/IPS) arkasında korunuyor.\n"
                f"Taramayı engellemek için gelen paketleri DROP etmektedir.\n\n"
                f"[💡 Çözüm]: Gerçek servis analizi çıktısını simüle etmek için terminalinizden "
                f"'python -m http.server 8888' komutuyla lokal bir servis başlatıp "
                f"'127.0.0.1' adresinde 8888 portunu test edin."
            )
            return jsonify({"port": port, "banner": firewall_msg, "is_firewall": True})
        else:
            return jsonify({"error": f"Hata: Bağlantı zaman aşımına uğradı (Timeout {connect_timeout}s)."}), 408
    except socket.gaierror:
        return jsonify({"error": "Hata: Hedef alan adı veya IP adresi çözümlenemedi (DNS Hatası). Lütfen adresi kontrol edin."}), 400
    except ConnectionRefusedError:
        return jsonify({
            "error": f"Hata: Port {port} kapalı veya servis çalışmıyor (Bağlantı reddedildi).",
            "note": "Hedef sunucu veya yerel güvenlik duvarınız (Firewall) bu portu engelliyor olabilir. Doğrulama için lokalde bir servis başlatıp '127.0.0.1' üzerinde test edebilirsiniz."
        }), 400
    except Exception as e:
        return jsonify({"error": f"Hata: Bağlantı kurulamadı: {str(e)}"})


@app.route("/api/crypto/hash", methods=["POST"])
def crypto_hash():
    data = request.json.get("target", "")
    return jsonify({
        "md5": hashlib.md5(data.encode()).hexdigest(),
        "sha1": hashlib.sha1(data.encode()).hexdigest(),
        "sha256": hashlib.sha256(data.encode()).hexdigest()
    })

@app.route("/api/crypto/crack", methods=["POST"])
def crypto_crack():
    target_hash = request.json.get("target", "").lower()
    hash_type = request.json.get("type", "md5")
    
    # Yerel mini sözlük
    wordlist = ["123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon", "admin", "root", "toor", "test", "demo", "kali", "pass", "qwe"]
    
    for word in wordlist:
        if hash_type == "md5" and hashlib.md5(word.encode()).hexdigest() == target_hash:
            return jsonify({"cracked": True, "password": word, "method": "Yerel Sözlük (Mini)"})
        elif hash_type == "sha1" and hashlib.sha1(word.encode()).hexdigest() == target_hash:
            return jsonify({"cracked": True, "password": word, "method": "Yerel Sözlük (Mini)"})
        elif hash_type == "sha256" and hashlib.sha256(word.encode()).hexdigest() == target_hash:
            return jsonify({"cracked": True, "password": word, "method": "Yerel Sözlük (Mini)"})
            
    # MD5 için çevrimiçi cloud veritabanını test et
    if hash_type == "md5":
        try:
             r = requests.get(f"http://www.nitrxgen.net/md5db/{target_hash}", timeout=3)
             if r.text and len(r.text) > 0:
                 return jsonify({"cracked": True, "password": r.text, "method": "Bulut Kırma Veritabanı"})
        except: pass

    return jsonify({"cracked": False, "error": "Şifre kırılamadı. Sözlükte veya veritabanında yok."})

@app.route("/api/scan/mac", methods=["POST"])
def mac_lookup():
    mac = request.json.get("target")
    try:
        url = f"https://api.macvendors.com/{mac}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return jsonify({"vendor": r.text})
        return jsonify({"error": "Ulaşılamadı veya geçersiz MAC."})
    except Exception as e:
        return jsonify({"error": str(e)})

def static_code_analyzer(code_content):
    import ast
    issues = []
    
    try:
        tree = ast.parse(code_content)
    except Exception as e:
        return [{
            "severity": "YÜKSEK",
            "confidence": "YÜKSEK",
            "line": 1,
            "issue": "Derleme / Sözdizimi Hatası",
            "details": f"Python kodu derlenirken sözdizimi hatası alındı: {str(e)}",
            "code": "N/A"
        }]
        
    for node in ast.walk(tree):
        # 1. eval / exec check
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                issues.append({
                    "severity": "YÜKSEK",
                    "confidence": "YÜKSEK",
                    "line": node.lineno,
                    "issue": f"Dinamik Kod Çalıştırma Zafiyeti ({node.func.id})",
                    "details": f"Güvensiz '{node.func.id}' fonksiyonu algılandı. Kullanıcı girdilerinin doğrudan eval/exec edilmesi Uzaktan Kod Yürütme (RCE) açıklarına zemin hazırlar.",
                    "code": f"{node.func.id}(...)"
                })
        
        # 2. subprocess / os.system check
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ['run', 'Popen', 'system', 'call']:
            is_shell_true = False
            for kw in node.keywords:
                if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    is_shell_true = True
            if is_shell_true or node.func.attr == 'system':
                issues.append({
                    "severity": "YÜKSEK",
                    "confidence": "YÜKSEK",
                    "line": node.lineno,
                    "issue": "Güvensiz Komut Satırı Yürütme (Command Injection)",
                    "details": f"'{node.func.attr}' çağrısında 'shell=True' veya doğrudan kabuk erişimi algılandı. Bu girdi filtrelenmezse Komut Satırı Enjeksiyonuna (OS Command Injection) yol açar.",
                    "code": f"subprocess.{node.func.attr}(..., shell=True)" if node.func.attr != 'system' else f"os.system(...)"
                })
                
        # 3. requests verify=False check
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ['get', 'post', 'put', 'delete']:
            for kw in node.keywords:
                if kw.arg == 'verify' and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    issues.append({
                        "severity": "ORTA",
                        "confidence": "YÜKSEK",
                        "line": node.lineno,
                        "issue": "SSL Sertifika Doğrulamasının Devre Dışı Bırakılması",
                        "details": "HTTP isteklerinde 'verify=False' kullanılarak sertifika kontrolü kapatılmış. Bu durum Ortadaki Adam (MitM) saldırılarına kapı açar.",
                        "code": f"requests.{node.func.attr}(..., verify=False)"
                    })
                    
        # 4. tempnam / mktemp check
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ['tempnam', 'mktemp']:
            issues.append({
                "severity": "DÜŞÜK",
                "confidence": "YÜKSEK",
                "line": node.lineno,
                "issue": "Güvensiz Geçici Dosya Oluşturucu",
                "details": f"Güvenli olmayan '{node.func.attr}' çağrısı yapıldı. Bunun yerine güvenli 'tempfile' sınıfının metodları kullanılmalıdır.",
                "code": f"tempfile.{node.func.attr}(...)"
            })
            
    # 5. Regex based hardcoded secret checks
    import re
    lines = code_content.splitlines()
    secret_pattern = re.compile(r'(password|passwd|secret|api_key|token|access_key|private_key)\s*=\s*[\'"][^\'"]{4,}[\'"]', re.IGNORECASE)
    for idx, line in enumerate(lines, 1):
        if secret_pattern.search(line) and not line.strip().startswith("#"):
            issues.append({
                "severity": "YÜKSEK",
                "confidence": "ORTA",
                "line": idx,
                "issue": "Sabit Kodlanmış Hassas Veri (Hardcoded Credentials)",
                "details": "Kod satırında sabit şifre, gizli anahtar veya API anahtarı ataması algılandı. Bu bilgiler yetkisiz erişim riski oluşturur.",
                "code": line.strip()
            })
            
    return issues


@app.route("/api/osint/breach", methods=["POST"])
def check_email_breach():
    email = request.json.get("target", "").strip()
    if not email:
        return jsonify({"error": "E-posta adresi belirtilmedi."}), 400
        
    try:
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        headers = {"User-Agent": "CyberSentinel-Academic-Project/1.0"}
        r = requests.get(url, headers=headers, timeout=5)
        
        if r.status_code == 200:
            data = r.json()
            breaches_list = data.get("breaches", [])
            parsed_breaches = []
            
            if isinstance(breaches_list, list):
                for b in breaches_list:
                    if isinstance(b, dict):
                        parsed_breaches.append({
                            "name": b.get("breach", "Bilinmeyen Sızıntı"),
                            "date": b.get("date", "N/A"),
                            "details": b.get("details", "Sızıntı detayları raporlanmadı.")
                        })
                    else:
                        parsed_breaches.append({
                            "name": str(b),
                            "date": "Bilinmiyor",
                            "details": "Veritabanı sızıntı kaydı."
                        })
            else:
                parsed_breaches.append({
                    "name": str(breaches_list),
                    "date": "Bilinmiyor",
                    "details": "XposedOrNot sızıntı kaydı."
                })
                
            return jsonify({"breached": True, "breaches": parsed_breaches})
        elif r.status_code == 404:
            return jsonify({"breached": False, "message": "Harika! E-posta adresi herhangi bir sızıntı veritabanında bulunamadı."})
        elif r.status_code == 429:
            return jsonify({"breached": False, "error": "Hız sınırı (Rate-Limit) aşıldı. Lütfen biraz bekleyin."})
        else:
            raise Exception(f"HTTP {r.status_code}")
    except Exception as e:
        # Fallback simulation
        simulated_domains = ["gmail.com", "hotmail.com", "yahoo.com", "live.com", "outlook.com"]
        domain = email.split("@")[-1] if "@" in email else ""
        if domain in simulated_domains:
            return jsonify({
                "breached": True,
                "breaches": [
                    {"name": "Adobe_Breach_Simulated", "date": "2013-10", "details": "Kullanıcı e-postaları, şifre ipuçları ve şifreli parolalar sızdırıldı."},
                    {"name": "LinkedIn_Breach_Simulated", "date": "2016-05", "details": "Linkedin kullanıcı veritabanı çalındı ve yayınlandı."}
                ],
                "simulated": True
            })
        return jsonify({"breached": False, "message": "E-posta adresi bilinen sızıntılarda bulunamadı (Yerel Simülasyon)."})


@app.route("/api/osint/virustotal", methods=["POST"])
def virustotal_scan():
    data = request.json
    target = data.get("target", "").strip()
    # API anahtarı yalnızca sunucu tarafında .env dosyasından okunur
    api_key = VIRUSTOTAL_API_KEY
    
    if not target:
        return jsonify({"error": "Analiz edilecek hedef belirtilmedi."}), 400
        
    if api_key:
        try:
            is_url = target.startswith("http") or "." in target and "/" in target
            headers = {"x-apikey": api_key}
            
            if is_url:
                submit_url = "https://www.virustotal.com/api/v3/urls"
                r_submit = requests.post(submit_url, data={"url": target}, headers=headers, timeout=8)
                if r_submit.status_code == 200:
                    analysis_id = r_submit.json().get("data", {}).get("id")
                    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    r_report = requests.get(report_url, headers=headers, timeout=8)
                    if r_report.status_code == 200:
                        stats = r_report.json().get("data", {}).get("attributes", {}).get("stats", {})
                        results = r_report.json().get("data", {}).get("attributes", {}).get("results", {})
                        parsed_results = []
                        for engine, res in list(results.items())[:10]:
                            parsed_results.append({
                                "engine": engine,
                                "category": res.get("category"),
                                "result": res.get("result") or "Temiz"
                            })
                        return jsonify({
                            "success": True,
                            "target": target,
                            "type": "URL",
                            "positives": stats.get("malicious", 0),
                            "total": sum(stats.values()),
                            "engines": parsed_results,
                            "real_api": True
                        })
            else:
                hash_url = f"https://www.virustotal.com/api/v3/files/{target}"
                r_hash = requests.get(hash_url, headers=headers, timeout=8)
                if r_hash.status_code == 200:
                    stats = r_hash.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    results = r_hash.json().get("data", {}).get("attributes", {}).get("last_analysis_results", {})
                    parsed_results = []
                    for engine, res in list(results.items())[:10]:
                        parsed_results.append({
                            "engine": engine,
                            "category": res.get("category"),
                            "result": res.get("result") or "Temiz"
                        })
                    return jsonify({
                        "success": True,
                        "target": target,
                        "type": "Hash",
                        "positives": stats.get("malicious", 0),
                        "total": sum(stats.values()),
                        "engines": parsed_results,
                        "real_api": True
                    })
                elif r_hash.status_code == 404:
                    return jsonify({"success": False, "error": "Dosya hash değeri VT veritabanında bulunamadı."})
                    
            return jsonify({"success": False, "error": "VirusTotal API geçersiz veya hatalı yanıt döndü."}), 400
        except Exception as e:
            return jsonify({"success": False, "error": f"VirusTotal Hatası: {str(e)}"}), 500
            
    # Simulation mode
    is_url = target.startswith("http") or "." in target
    engines = ["Kaspersky", "Sophos", "Symantec", "Bitdefender", "Avast", "McAfee", "ESET-NOD32", "Microsoft Defender", "FireEye", "CrowdStrike"]
    is_threat = any(x in target.lower() for x in ["malware", "virus", "phishing", "trojan", "hack", "test"]) or (len(target) % 7 == 0)
    
    positives = 3 if is_threat else 0
    parsed_results = []
    for i, eng in enumerate(engines):
        category = "clean"
        result = "Clean / Temiz"
        if is_threat and i in [0, 2, 6]:
            category = "malicious"
            result = "Malware / Phishing Detected"
        parsed_results.append({
            "engine": eng,
            "category": category,
            "result": result
        })
        
    return jsonify({
        "success": True,
        "target": target,
        "type": "URL" if is_url else "Hash",
        "positives": positives,
        "total": len(engines),
        "engines": parsed_results,
        "real_api": False,
        "simulation_msg": "API Anahtarı girilmediği için yerel tehdit istihbaratı veritabanı simülasyonu çalıştırılmıştır."
    })


@app.route("/api/security/code-scan", methods=["POST"])
def scan_code():
    import tempfile
    import json
    code_content = request.json.get("target", "")
    if not code_content:
        return jsonify({"error": "Analiz edilecek kod içeriği boş olamaz."}), 400
        
    # Try running bandit via subprocess
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as f:
        f.write(code_content)
        temp_path = f.name
        
    try:
        res = subprocess.run(["bandit", "-f", "json", temp_path], capture_output=True, text=True)
        data = json.loads(res.stdout)
        issues = []
        for issue in data.get("results", []):
            severity_map = {"HIGH": "YÜKSEK", "MEDIUM": "ORTA", "LOW": "DÜŞÜK"}
            issues.append({
                "severity": severity_map.get(issue.get("issue_severity"), "DÜŞÜK"),
                "confidence": issue.get("issue_confidence", "YÜKSEK"),
                "line": issue.get("line_number", 1),
                "issue": issue.get("issue_text", "Güvenlik Zafiyeti"),
                "details": issue.get("more_info", "Bandit tarafından tespit edildi."),
                "code": issue.get("code", "").strip()
            })
        os.remove(temp_path)
        return jsonify({"issues": issues})
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
        issues = static_code_analyzer(code_content)
        return jsonify({"issues": issues})


@app.route("/api/security/password-check", methods=["POST"])
def check_password():
    password = request.json.get("target", "")
    if not password:
        return jsonify({"error": "Analiz edilecek parola boş olamaz."}), 400
        
    # Read rockyou.txt
    is_common = False
    rockyou_path = os.path.join(base_path, "rockyou.txt")
    if os.path.exists(rockyou_path):
        try:
            with open(rockyou_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.strip() == password:
                        is_common = True
                        break
        except:
            pass
            
    if not is_common:
        common_passwords = ["123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon", "admin", "root", "toor", "test", "demo", "kali", "pass", "qwe"]
        is_common = password.lower() in common_passwords
    
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_special: pool_size += 32
    
    if pool_size == 0 or len(password) == 0:
        entropy = 0
    else:
        import math
        entropy = len(password) * math.log2(pool_size)
        
    if entropy < 30 or is_common:
        strength = "ÇOK ZAYIF"
        color = "var(--accent-red)"
        level = 1
    elif entropy < 50:
        strength = "ZAYIF"
        color = "#eab308"
        level = 2
    elif entropy < 72:
        strength = "ORTA"
        color = "var(--accent-blue)"
        level = 3
    else:
        strength = "GÜÇLÜ"
        color = "var(--accent-green)"
        level = 4
        
    guesses = pool_size ** len(password) if pool_size > 0 else 0
    seconds_to_crack = guesses / 1000000.0 if guesses > 0 else 0
    
    if seconds_to_crack < 1:
        crack_time = "Anında (1 saniyeden kısa)"
    elif seconds_to_crack < 60:
        crack_time = f"{int(seconds_to_crack)} saniye"
    elif seconds_to_crack < 3600:
        crack_time = f"{int(seconds_to_crack/60)} dakika"
    elif seconds_to_crack < 86400:
        crack_time = f"{int(seconds_to_crack/3600)} saat"
    elif seconds_to_crack < 31536000:
        crack_time = f"{int(seconds_to_crack/86400)} gün"
    elif seconds_to_crack < 3153600000:
        crack_time = f"{int(seconds_to_crack/31536000)} yıl"
    else:
        crack_time = "Yüzyıllar (Asırlar boyu kırılamaz)"
        
    return jsonify({
        "entropy": round(entropy, 2),
        "strength": strength,
        "color": color,
        "level": level,
        "is_common": is_common,
        "crack_time": crack_time,
        "character_pool": pool_size,
        "length": len(password)
    })

@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    data = request.json
    message = data.get("message", "")
    # API anahtarı yalnızca sunucu tarafında .env dosyasından okunur
    api_key = GEMINI_API_KEY
    
    if not message:
        return jsonify({"error": "Mesaj boş olamaz."}), 400
        
    if api_key:
        if api_key.startswith("sk-"):
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "system",
                        "content": "Sen Cyber Sentinel siber güvenlik istasyonunun yerleşik AI asistanısın. Görevin kullanıcılara siber güvenlik konularında, zafiyet analizlerinde, port ve ağ tarama sonuçlarının yorumlanmasında Türkçe dilinde, teknik açıdan doğru, öğretici ve profesyonel rehberlik sağlamaktır. Cevaplarını siber güvenlik en iyi pratiklerine göre (OWASP, NIST vb.) oluştur."
                    },
                    {
                        "role": "user",
                        "content": message
                    }
                ]
            }
            try:
                res = requests.post(url, json=payload, headers=headers, timeout=35)
                if res.status_code == 200:
                    res_data = res.json()
                    choices = res_data.get("choices", [])
                    if choices:
                        content = choices[0].get("message", {}).get("content", "Boş yanıt döndü.")
                        return jsonify({"response": content})
                return jsonify({"response": f"OpenAI API Hatası: Sunucu {res.status_code} durum kodu döndü. Yanıt: {res.text[:150]}"})
            except Exception as e:
                return jsonify({"response": f"Bağlantı Hatası: OpenAI API'ye erişilemedi. Hata detayı: {str(e)}"})
        else:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [
                    {
                        "parts": [
                            {
                                "text": "Sen Cyber Sentinel siber güvenlik istasyonunun yerleşik AI asistanısın. Görevin kullanıcılara siber güvenlik konularında, zafiyet analizlerinde, port ve ağ tarama sonuçlarının yorumlanmasında Türkçe dilinde, teknik açıdan doğru, öğretici ve profesyonel rehberlik sağlamaktır. Cevaplarını siber güvenlik en iyi pratiklerine göre (OWASP, NIST vb.) oluştur."
                            },
                            {
                                "text": message
                            }
                        ]
                    }
                ]
            }
            try:
                res = requests.post(url, json=payload, headers=headers, timeout=35)
                if res.status_code == 200:
                    res_data = res.json()
                    candidates = res_data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            return jsonify({"response": parts[0].get("text", "Boş yanıt döndü.")})
                return jsonify({"response": f"Gemini API Hatası: Sunucu {res.status_code} durum kodu döndü. Yanıt: {res.text[:150]}"})
            except Exception as e:
                return jsonify({"response": f"Bağlantı Hatası: Gemini API'ye erişilemedi. Hata detayı: {str(e)}"})
            
    # Simulation mode
    prompt_lower = message.lower()
    if "port" in prompt_lower:
        reply = (
            "**[SİBER GÜVENLİK YEREL VERİTABANI ANALİZİ]**\n\n"
            "Keşfedilen açık port bulgularınız incelenmiştir:\n"
            "1. **Risk Analizi**: Port 22 (SSH) veya Port 80/443 (HTTP/HTTPS) gibi portların açık olması, saldırganlar için potansiyel bir giriş noktası teşkil eder. Açık servislerin sürüm zafiyetleri veya zayıf parolaları brute-force saldırılarına zemin hazırlar.\n"
            "2. **Çözüm Önerileri**:\n"
            "   - SSH için parolasız kimlik doğrulama (SSH Key) kullanın ve root girişini kapatın.\n"
            "   - Güvenlik duvarı (UFW / iptables) ile sadece belirli IP'lerin açık servislere erişimine izin verin.\n"
            "   - Gereksiz servisleri devre dışı bırakarak saldırı yüzeyini küçültün."
        )
    elif "ping" in prompt_lower:
        reply = (
            "**[SİBER GÜVENLİK YEREL VERİTABANI ANALİZİ]**\n\n"
            "Ping (ICMP) keşif analizi sonuçları:\n"
            "1. **Tehdit Bulgusu**: Hedef makinenin ICMP Echo isteklerine yanıt vermesi ağda aktif olduğunu doğrular. Saldırganlar ağ keşif (reconnaissance) aşamasında ping taramalarıyla canlı hedefleri belirler.\n"
            "2. **Savunma Önlemleri**:\n"
            "   - Güvenlik duvarınızda (Firewall) dışarıdan gelen ICMP Echo isteklerini engelleyecek kurallar tanımlayın (ICMP Drop).\n"
            "   - IDS/IPS sistemlerini ağda konumlandırarak yoğun ping taramalarını (Ping Sweep) tespit edip engelleyin."
        )
    elif "zafiyet" in prompt_lower or "sast" in prompt_lower or "kod" in prompt_lower:
        reply = (
            "**[SİBER GÜVENLİK YEREL VERİTABANI ANALİZİ]**\n\n"
            "Kaynak kod zafiyet analiz sonuçları:\n"
            "1. **Kritik Bulgular**:\n"
            "   - **eval() / exec()** kullanımı: Kullanıcıdan gelen kontrol edilmeyen verilerin sistemde doğrudan çalıştırılmasına (RCE) yol açar.\n"
            "   - **os.system()** kullanımı: Kabuk parametresi birleştirilerek kullanılıyorsa komut enjeksiyonu riski taşır.\n"
            "2. **Güvenli Tasarım**:\n"
            "   - eval() yerine `ast.literal_eval` gibi güvenli kütüphaneleri kullanın.\n"
            "   - os.system yerine `subprocess.run(..., shell=False)` kullanarak komut argümanlarını dizi olarak geçirin."
        )
    else:
        reply = (
            "**[SİBER GÜVENLİK YEREL VERİTABANI ANALİZİ]**\n\n"
            "Ben Cyber Sentinel siber güvenlik danışmanıyım. Güvenlik analizlerine ve sorularınıza yanıt vermeye hazırım.\n"
            "Örn: 'Port tarama riskleri nelerdir?' veya 'SQL Injection nasıl engellenir?'\n\n"
            "*Not: Gerçek zamanlı ve dinamik yapay zeka analizleri için yukarıdaki Ayarlar panelinden geçerli bir **Google Gemini API Key** girmeniz gerekmektedir.*"
        )
        
    return jsonify({"response": reply})

@app.route("/api/ai/triage", methods=["POST"])
def ai_triage():
    data = request.json
    code = data.get("code", "")
    # API anahtarı yalnızca sunucu tarafında .env dosyasından okunur
    api_key = GEMINI_API_KEY
    
    if not code:
        return jsonify({"error": "Analiz edilecek kod boş olamaz."}), 400
        
    if api_key:
        import json
        if api_key.startswith("sk-"):
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            prompt = f"""Aşağıdaki Python kodunu siber güvenlik uzmanı gözüyle analiz et.
Kod:
{code}

Yanıtını kesinlikle ve sadece aşağıdaki JSON formatında ver. Başka hiçbir şey yazma (markdown codeblock'ları olan ```json ... ``` kullanabilirsin):
{{
  "score": <1-100 arası zafiyet ciddiyet puanı (sayı)>,
  "false_positive": <bu kodda gerçekten bir zafiyet var mı yoksa sahte bir uyarı mı? (true veya false bool değeri)>,
  "attack_surface": "<kısa saldırı yüzeyi tanımı, örn: RCE, SQLi, Command Injection vb.>",
  "analysis": "<zafiyetlerin detaylı Türkçe açıklaması ve risk analizi>",
  "secure_code": "<kodun zafiyetten arındırılmış güvenli hali (remediation)>"
}}
"""
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "response_format": {"type": "json_object"}
            }
            try:
                res = requests.post(url, json=payload, headers=headers, timeout=35)
                if res.status_code == 200:
                    res_data = res.json()
                    choices = res_data.get("choices", [])
                    if choices:
                        text_res = choices[0].get("message", {}).get("content", "").strip()
                        parsed = json.loads(text_res)
                        return jsonify(parsed)
            except Exception as e:
                pass
        else:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
            headers = {"Content-Type": "application/json"}
            prompt = f"""Aşağıdaki Python kodunu siber güvenlik uzmanı gözüyle analiz et.
Kod:
{code}

Yanıtını kesinlikle ve sadece aşağıdaki JSON formatında ver. Başka hiçbir şey yazma (markdown codeblock'ları olan ```json ... ``` kullanabilirsin):
{{
  "score": <1-100 arası zafiyet ciddiyet puanı (sayı)>,
  "false_positive": <bu kodda gerçekten bir zafiyet var mı yoksa sahte bir uyarı mı? (true veya false bool değeri)>,
  "attack_surface": "<kısa saldırı yüzeyi tanımı, örn: RCE, SQLi, Command Injection vb.>",
  "analysis": "<zafiyetlerin detaylı Türkçe açıklaması ve risk analizi>",
  "secure_code": "<kodun zafiyetten arındırılmış güvenli hali (remediation)>"
}}
"""
            payload = {
                "contents": [{"parts": [{"text": prompt}]}]
            }
            try:
                res = requests.post(url, json=payload, headers=headers, timeout=35)
                if res.status_code == 200:
                    res_data = res.json()
                    candidates = res_data.get("candidates", [])
                    if candidates:
                        text_res = candidates[0].get("content", {}).get("parts", [])[0].get("text", "").strip()
                        if text_res.startswith("```"):
                            lines = text_res.splitlines()
                            if lines[0].startswith("```"):
                                lines = lines[1:]
                            if lines and lines[-1].startswith("```"):
                                lines = lines[:-1]
                            text_res = "\n".join(lines).strip()
                        
                        parsed = json.loads(text_res)
                        return jsonify(parsed)
            except Exception as e:
                pass
            
    # Simulation Triage
    score = 15
    false_positive = True
    attack_surface = "Düşük Risk / Temiz Kod"
    analysis = "Kod içerisinde kritik bir güvensiz fonksiyon (eval, system, exec vb.) veya sabit kodlanmış parola tespit edilememiştir. Genel güvenlik kurallarına uygun görünmektedir."
    secure_code = code
    
    if "eval(" in code or "exec(" in code:
        score = 85
        false_positive = False
        attack_surface = "Uzaktan Kod Yürütme (RCE)"
        analysis = "Kod içerisinde eval() veya exec() dinamik çalıştırma fonksiyonu algılanmıştır. Kullanıcı tarafından manipüle edilebilecek girdiler doğrudan sistemde çalıştırılarak tam sistem ele geçirme zafiyetine yol açar."
        secure_code = code.replace("eval(", "# Güvenli alternatif (ast.literal_eval kullanın):\n# import ast\n# ast.literal_eval(")
    elif "system(" in code or "subprocess.Popen" in code or "subprocess.run" in code:
        score = 75
        false_positive = False
        attack_surface = "İşletim Sistemi Komut Enjeksiyonu"
        analysis = "İşletim sistemi komut satırı tetikleyicisi (os.system / subprocess) tespit edilmiştir. Komutlar string birleştirme ile oluşturuluyorsa, saldırgan komut sonuna '; rm -rf' gibi eklemeler yaparak sistem komutları yürütebilir."
        secure_code = "# Güvenli alternatif (shell=False kullanın):\n# import subprocess\n# subprocess.run(['ping', '-c', '2', ip], shell=False)"
    elif "password =" in code or "api_key =" in code or "secret =" in code:
        score = 65
        false_positive = False
        attack_surface = "Hassas Bilgilerin Kodda Saklanması"
        analysis = "Kod içerisinde sabit atanmış şifre veya API anahtarı tanımlaması tespit edilmiştir. Kod tabanı çalındığında veya yetkisiz erişimde bu hassas anahtarlar ele geçirilir."
        secure_code = "# Güvenli alternatif (Ortam değişkeni kullanın):\n# import os\n# api_key = os.environ.get('API_KEY')"
        
    return jsonify({
        "score": score,
        "false_positive": false_positive,
        "attack_surface": attack_surface,
        "analysis": f"[SİMÜLE RAPOR] {analysis}",
        "secure_code": secure_code
    })

# ─────────────────────────────────────────────
# KRİPTOGRAFİ LABORATUVARI ENDPOINTLERİ
# ─────────────────────────────────────────────

# Türkçe karakter uyumlu alfabe
TR_ALPHABET = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZabcçdefgğhıijklmnoöprsştuüvyz"
TR_UPPER    = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ"
TR_LOWER    = "abcçdefgğhıijklmnoöprsştuüvyz"

def _caesar_shift(text, shift, decrypt=False):
    """Türkçe karakter uyumlu Sezar şifreleme / çözme."""
    if decrypt:
        shift = -shift
    result = []
    for ch in text:
        if ch in TR_UPPER:
            idx = (TR_UPPER.index(ch) + shift) % len(TR_UPPER)
            result.append(TR_UPPER[idx])
        elif ch in TR_LOWER:
            idx = (TR_LOWER.index(ch) + shift) % len(TR_LOWER)
            result.append(TR_LOWER[idx])
        else:
            result.append(ch)
    return "".join(result)

def _vigenere(text, key, decrypt=False):
    """Türkçe karakter uyumlu Vigenère şifreleme / çözme."""
    key_upper = key.upper()
    key_clean = [c for c in key_upper if c in TR_UPPER]
    if not key_clean:
        return text, "Anahtar geçerli karakter içermiyor."
    result = []
    ki = 0
    for ch in text:
        if ch in TR_UPPER or ch in TR_LOWER:
            is_lower = ch in TR_LOWER
            alpha = TR_LOWER if is_lower else TR_UPPER
            ch_up = ch.upper() if is_lower else ch
            if ch_up not in TR_UPPER:
                result.append(ch)
                continue
            c_idx = TR_UPPER.index(ch_up)
            k_idx = TR_UPPER.index(key_clean[ki % len(key_clean)])
            if decrypt:
                new_idx = (c_idx - k_idx) % len(TR_UPPER)
            else:
                new_idx = (c_idx + k_idx) % len(TR_UPPER)
            new_ch = TR_UPPER[new_idx]
            result.append(new_ch.lower() if is_lower else new_ch)
            ki += 1
        else:
            result.append(ch)
    return "".join(result)

@app.route("/api/crypto/cipher", methods=["POST"])
def crypto_cipher():
    """Kriptografi Laboratuvarı: Sezar, Vigenère, AES-256, DES, RSA"""
    import base64
    data      = request.json
    algorithm = data.get("algorithm", "caesar").lower()
    mode      = data.get("mode", "encrypt")       # "encrypt" | "decrypt"
    plaintext = data.get("text", "")
    key_raw   = data.get("key", "")
    decrypt   = (mode == "decrypt")

    if not plaintext:
        return jsonify({"error": "Metin boş olamaz."}), 400

    # ── SEZAR ──────────────────────────────────────────────
    if algorithm == "caesar":
        try:
            shift = int(key_raw) if key_raw else 3
            shift = shift % len(TR_UPPER)
        except ValueError:
            return jsonify({"error": "Sezar için anahtar bir tam sayı (örn: 3) olmalıdır."}), 400
        result = _caesar_shift(plaintext, shift, decrypt=decrypt)
        analysis = (
            f"[⚠️ Güvenlik Analizi]: Sezar şifreleme KRİTİK DERECEDE GÜVENSİZDİR.\n"
            f"Yalnızca {len(TR_UPPER)} farklı anahtar olasılığı mevcuttur.\n"
            f"Kaba kuvvet (Brute-Force) ile {len(TR_UPPER)} denemede, frekans analizi ile\n"
            f"ise çoğunlukla tek denemede saniyeler içinde kırılabilir."
        )
        return jsonify({"result": result, "analysis": analysis})

    # ── VİGENÈRE ───────────────────────────────────────────
    elif algorithm == "vigenere":
        if not key_raw:
            return jsonify({"error": "Vigenère için bir anahtar kelime girilmelidir."}), 400
        result = _vigenere(plaintext, key_raw, decrypt=decrypt)
        key_space = len(TR_UPPER) ** len(key_raw)
        analysis = (
            f"[⚠️ Güvenlik Analizi]: Vigenère, Sezar'dan güçlüdür ancak hâlâ kırılabilirdir.\n"
            f"'{key_raw}' uzunluğundaki anahtar için anahtar uzayı yaklaşık {key_space:,} kombinasyon.\n"
            f"Kasiski Testi veya Friedman İndeks Analizi ile kısa anahtarlar dakikalar içinde\n"
            f"açığa çıkarılabilir. Güvenli iletişim için AES-256 kullanılmalıdır."
        )
        return jsonify({"result": result, "analysis": analysis})

    # ── AES-256 CBC ────────────────────────────────────────
    elif algorithm == "aes":
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
            from Crypto.Hash import SHA256
            import base64, os as _os
            if not key_raw:
                return jsonify({"error": "AES için bir parola (passphrase) girilmelidir."}), 400
            # SHA-256 ile 32 byte'lık anahtar türet
            key_bytes = SHA256.new(key_raw.encode("utf-8")).digest()
            if not decrypt:
                iv = _os.urandom(16)
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                ct = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
                result = base64.b64encode(iv + ct).decode("utf-8")
            else:
                raw = base64.b64decode(plaintext.strip())
                iv, ct = raw[:16], raw[16:]
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                result = unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")
            analysis = (
                "[🛡️ Güvenlik Analizi]: AES-256 ASKERİ STANDART şifrelemedir.\n"
                "256-bit anahtar uzayı 2²⁵⁶ kombinasyon barındırır.\n"
                "Tüm süper bilgisayarlar paralel çalışsa bile kırılması\n"
                "evrenin ömründen trilyonlarca kat daha uzun sürerdi.\n"
                "TLS/HTTPS, askeri iletişim ve disk şifrelemede kullanılır."
            )
            return jsonify({"result": result, "analysis": analysis})
        except Exception as e:
            return jsonify({"error": f"AES Hatası: {str(e)}"}), 500

    # ── DES CBC ────────────────────────────────────────────
    elif algorithm == "des":
        try:
            from Crypto.Cipher import DES
            from Crypto.Util.Padding import pad, unpad
            import base64, os as _os
            # DES anahtarı tam olarak 8 byte
            key_bytes = key_raw.encode("utf-8")
            if len(key_bytes) < 8:
                key_bytes = key_bytes.ljust(8, b'\x00')
            key_bytes = key_bytes[:8]
            if not decrypt:
                iv = _os.urandom(8)
                cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
                ct = cipher.encrypt(pad(plaintext.encode("utf-8"), DES.block_size))
                result = base64.b64encode(iv + ct).decode("utf-8")
            else:
                raw = base64.b64decode(plaintext.strip())
                iv, ct = raw[:8], raw[8:]
                cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
                result = unpad(cipher.decrypt(ct), DES.block_size).decode("utf-8")
            analysis = (
                "[⚠️ Güvenlik Analizi]: DES (Data Encryption Standard) 1977'den beri\n"
                "kullanılmaktadır ancak 56-bit anahtar uzayı KIRILMIŞ olup\n"
                "1999'da 22 saatte brute-force ile çözülmüştür.\n"
                "NIST tarafından 2005'te resmi olarak emekliye ayrılmıştır.\n"
                "Sadece akademik/eğitim amaçlıdır. Üretimde AES kullanın!"
            )
            return jsonify({"result": result, "analysis": analysis})
        except Exception as e:
            return jsonify({"error": f"DES Hatası: {str(e)}"}), 500

    # ── RSA 2048 ───────────────────────────────────────────
    elif algorithm == "rsa":
        try:
            from Crypto.PublicKey import RSA
            from Crypto.Cipher import PKCS1_OAEP
            import base64
            if not key_raw:
                return jsonify({"error": "RSA için Public Key (şifrele) veya Private Key (çöz) girilmelidir."}), 400
            key_obj = RSA.import_key(key_raw.strip())
            if not decrypt:
                cipher = PKCS1_OAEP.new(key_obj.publickey() if key_obj.has_private() else key_obj)
                ct = cipher.encrypt(plaintext.encode("utf-8"))
                result = base64.b64encode(ct).decode("utf-8")
            else:
                if not key_obj.has_private():
                    return jsonify({"error": "RSA çözme için Private Key gereklidir."}), 400
                cipher = PKCS1_OAEP.new(key_obj)
                pt = cipher.decrypt(base64.b64decode(plaintext.strip()))
                result = pt.decode("utf-8")
            analysis = (
                "[🔐 Güvenlik Analizi]: RSA-2048 asimetrik şifreleme standardıdır.\n"
                "Public Key ile şifrelenmiş veri SADECE Private Key ile çözülebilir.\n"
                "2048-bit anahtar için asal çarpanlara ayırma problemi\n"
                "mevcut teknoloji ile çözülememektedir.\n"
                "TLS, e-posta şifrelemesi (PGP) ve dijital imzalarda kullanılır."
            )
            return jsonify({"result": result, "analysis": analysis})
        except Exception as e:
            return jsonify({"error": f"RSA Hatası: {str(e)}"}), 500

    return jsonify({"error": f"Bilinmeyen algoritma: {algorithm}"}), 400


@app.route("/api/crypto/rsa-keygen", methods=["POST"])
def rsa_keygen():
    """RSA anahtar çifti üretimi (2048-bit)"""
    try:
        from Crypto.PublicKey import RSA
        bits = request.json.get("bits", 2048)
        if bits not in [1024, 2048, 4096]:
            bits = 2048
        key = RSA.generate(bits)
        private_key = key.export_key("PEM").decode("utf-8")
        public_key  = key.publickey().export_key("PEM").decode("utf-8")
        return jsonify({
            "private_key": private_key,
            "public_key":  public_key,
            "bits": bits
        })
    except Exception as e:
        return jsonify({"error": f"Anahtar üretimi başarısız: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────
# DOS STRES TESTİ ENDPOINTİ
# ─────────────────────────────────────────────────────────────
@app.route("/api/stress/dos", methods=["POST"])
def dos_stress_test():
    import time as _time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    data         = request.json
    target_url   = data.get("url", "").strip()
    thread_count = min(int(data.get("threads", 5)), 20)    # Maks 20 thread
    req_count    = min(int(data.get("requests", 20)), 100)  # Maks 100 istek

    if not target_url:
        return jsonify({"error": "URL belirtilmedi."}), 400
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    results = []

    def make_request(idx):
        try:
            t0 = _time.time()
            r  = requests.get(target_url, timeout=5, verify=False, allow_redirects=True)
            ms = round((_time.time() - t0) * 1000, 1)
            return {"index": idx, "status": r.status_code, "time_ms": ms, "success": True}
        except Exception as e:
            return {"index": idx, "status": 0, "time_ms": 0, "success": False, "error": str(e)[:60]}

    with ThreadPoolExecutor(max_workers=thread_count) as ex:
        futures = [ex.submit(make_request, i) for i in range(req_count)]
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda x: x["index"])
    times        = [r["time_ms"] for r in results if r["success"] and r["time_ms"] > 0]
    success_cnt  = sum(1 for r in results if r["success"])

    return jsonify({
        "results":  results,
        "summary": {
            "total":    req_count,
            "success":  success_cnt,
            "failed":   req_count - success_cnt,
            "avg_ms":   round(sum(times) / len(times), 1) if times else 0,
            "min_ms":   min(times) if times else 0,
            "max_ms":   max(times) if times else 0,
            "target":   target_url
        }
    })


# ─────────────────────────────────────────────────────────────
# OTURUM & ÇEREZ ANALİZİ (XSS / Güvenlik Başlıkları)
# ─────────────────────────────────────────────────────────────
@app.route("/api/security/session-check", methods=["POST"])
def session_check():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    target_url = request.json.get("target", "").strip()
    if not target_url:
        return jsonify({"error": "URL belirtilmedi."}), 400
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    try:
        r       = requests.get(target_url, timeout=8, verify=False, allow_redirects=True)
        headers = dict(r.headers)
        cookies = r.cookies

        findings   = []
        score      = 100
        cookie_list = []

        for ck in cookies:
            is_httponly = ck.has_nonstandard_attr("HttpOnly")
            is_secure   = bool(ck.secure)
            cookie_list.append({
                "name":     ck.name,
                "value":    (ck.value[:20] + "...") if len(ck.value) > 20 else ck.value,
                "httponly": is_httponly,
                "secure":   is_secure,
                "domain":   ck.domain or "N/A"
            })
            if not is_secure:
                findings.append({"severity": "YÜKSEK",
                                  "issue": f"'{ck.name}' çerezi Secure bayrağı taşımıyor",
                                  "detail": "HTTP üzerinden gönderilebilir; MitM saldırısında ele geçirilebilir."})
                score -= 15
            if not is_httponly:
                findings.append({"severity": "YÜKSEK",
                                  "issue": f"'{ck.name}' çerezi HttpOnly bayrağı taşımıyor",
                                  "detail": "JavaScript erişimine açık; XSS saldırısıyla çalınabilir."})
                score -= 15

        SEC_HEADERS = {
            "Content-Security-Policy":   ("YÜKSEK", "XSS ve veri enjeksiyonunu engeller."),
            "X-Frame-Options":           ("ORTA",   "Clickjacking saldırılarını engeller."),
            "X-Content-Type-Options":    ("ORTA",   "MIME-sniffing saldırılarını engeller."),
            "Strict-Transport-Security": ("YÜKSEK", "SSL stripping ve HTTPS zorlaması sağlar."),
            "X-XSS-Protection":          ("DÜŞÜK",  "Tarayıcı XSS filtrelerini aktive eder."),
            "Referrer-Policy":           ("DÜŞÜK",  "Referrer bilgisi sızıntısını önler."),
            "Permissions-Policy":        ("DÜŞÜK",  "Kamera/Mikrofon API erişimlerini kısıtlar."),
        }
        found_headers = {}
        for hname, (sev, detail) in SEC_HEADERS.items():
            val = headers.get(hname, "")
            found_headers[hname] = val if val else None
            if not val:
                findings.append({"severity": sev, "issue": f"Eksik güvenlik başlığı: {hname}", "detail": detail})
                score -= {"YÜKSEK": 20, "ORTA": 10, "DÜŞÜK": 5}[sev]

        return jsonify({
            "target":         target_url,
            "status_code":    r.status_code,
            "cookies":        cookie_list,
            "sec_headers":    found_headers,
            "findings":       findings,
            "security_score": max(0, score)
        })
    except Exception as e:
        return jsonify({"error": f"Bağlantı hatası: {str(e)}"}), 500


# ─────────────────────────────────────────────────────────────
# YENİ MODÜL: OTURUM & ÇEREZ ANALİZİ (CANLI KONSOL VE THREADING)
# ─────────────────────────────────────────────────────────────
import uuid
import threading

cookie_analysis_logs = {}

@app.route("/api/security/cookie-analyze", methods=["POST"])
def cookie_analyze():
    target_url = request.json.get("target", "").strip()
    if not target_url:
        return jsonify({"error": "URL belirtilmedi."}), 400
        
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    analysis_id = str(uuid.uuid4())
    cookie_analysis_logs[analysis_id] = []

    def background_analysis(url, aid):
        logs = cookie_analysis_logs[aid]
        logs.append("[+] Oturum Güvenliği Analizi Başlatıldı...")
        logs.append(f"[+] Hedef: {url}")
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Siteye istek gönderiyoruz
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            logs.append(f"[+] Yanıt alındı. Durum Kodu: {response.status_code}")
            
            # 1. CSP (Content Security Policy) Kontrolü
            csp_found = False
            # Büyük/küçük harf duyarlılığını aşmak için başlıkları küçük harfe çevirip arıyoruz
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            if 'content-security-policy' in headers_lower:
                csp_found = True
            
            if not csp_found:
                logs.append("[!] KRİTİK: Sitede Content-Security-Policy (CSP) koruması bulunamadı! (XSS ve kod enjeksiyonu riski!)")
            else:
                logs.append("[+] OK: Content-Security-Policy (CSP) koruması aktif.")

            # 2. Çerez (Cookie) Politikaları Kontrolü
            if not response.cookies:
                logs.append("[-] Bilgi: Hedef site bu istek için herhangi bir çerez (cookie) bırakmadı.")
            else:
                for cookie in response.cookies:
                    logs.append(f"\n--- Çerez Analizi: {cookie.name} ---")
                    
                    # HttpOnly Kontrolü (Hata vermeyen standart yöntem)
                    is_httponly = False
                    if cookie._rest and 'httponly' in [k.lower() for k in cookie._rest.keys()]:
                        is_httponly = True
                    
                    if not is_httponly:
                        logs.append(f"[!] UYARI: '{cookie.name}' çerezinde HttpOnly bayrağı eksik! (XSS ile oturum çalınabilir!)")
                    else:
                        logs.append(f"[+] OK: '{cookie.name}' çerezi HttpOnly ile korunuyor.")
                        
                    # Secure Kontrolü
                    if not cookie.secure:
                        logs.append(f"[!] UYARI: '{cookie.name}' çerezinde Secure bayrağı eksik! (Ağ koklayıcılar şifresiz çekebilir!)")
                    else:
                        logs.append(f"[+] OK: '{cookie.name}' çerezi Secure (Şifreli) modda.")
                        
                    # SameSite Kontrolü
                    samesite_attrs = []
                    if cookie._rest:
                        samesite_attrs = [v for k, v in cookie._rest.items() if k.lower() == 'samesite']
                    if not samesite_attrs:
                        logs.append(f"[!] UYARI: '{cookie.name}' çerezinde SameSite özniteliği eksik! (CSRF riski!)")
                    else:
                        logs.append(f"[+] OK: '{cookie.name}' çerezi SameSite={samesite_attrs[0]} değerine sahip.")
                        
            logs.append("\n[+] Analiz Başarıyla Tamamlandı.")
            
        except requests.exceptions.RequestException as e:
            logs.append(f"[Hata]: Web sitesine bağlanılamadı. Geçerli bir URL girdiğinizden emin olun. Detay: {e}")
        except Exception as e:
            logs.append(f"[Hata]: Analiz sırasında beklenmeyen bir hata oluştu: {e}")

    # Threading ile arka planda çalıştırıyoruz
    thread = threading.Thread(target=background_analysis, args=(target_url, analysis_id))
    thread.daemon = True
    thread.start()

    return jsonify({"analysis_id": analysis_id})

@app.route("/api/security/cookie-analyze/logs/<analysis_id>", methods=["GET"])
def cookie_analyze_logs(analysis_id):
    logs = cookie_analysis_logs.get(analysis_id)
    if logs is None:
        return jsonify({"error": "Geçersiz analiz kimliği."}), 404
        
    is_done = False
    if len(logs) > 0 and (logs[-1] == "[+] Analiz Tamamlandı." or logs[-1].startswith("[Hata]")):
        is_done = True
        
    return jsonify({
        "logs": logs,
        "done": is_done
    })



# ─────────────────────────────────────────────────────────────
# SHODAN IP KEŞFİ (OSINT)
# ─────────────────────────────────────────────────────────────
@app.route("/api/osint/shodan", methods=["POST"])
def shodan_lookup():
    target_ip = request.json.get("target", "").strip()
    api_key   = os.environ.get("SHODAN_API_KEY", "")

    if not target_ip:
        return jsonify({"error": "IP adresi belirtilmedi."}), 400

    if api_key:
        try:
            import shodan as _shodan
            api  = _shodan.Shodan(api_key)
            host = api.host(target_ip)
            return jsonify({
                "ip":        target_ip,
                "country":   host.get("country_name", "Bilinmiyor"),
                "city":      host.get("city", "Bilinmiyor"),
                "org":       host.get("org", "Bilinmiyor"),
                "isp":       host.get("isp", "Bilinmiyor"),
                "os":        host.get("os", "Bilinmiyor"),
                "hostnames": host.get("hostnames", []),
                "open_ports":host.get("ports", []),
                "services":  [{"port": s.get("port"), "transport": s.get("transport","tcp"),
                                "product": s.get("product",""), "version": s.get("version",""),
                                "banner": s.get("data","")[:100]}
                               for s in host.get("data", [])[:10]],
                "real_api":  True
            })
        except Exception:
            pass  # API yoksa simülasyona düş

    # Simülasyon modu
    return jsonify({
        "ip":         target_ip,
        "country":    "Türkiye (Simüle)",
        "city":       "İstanbul",
        "org":        "Türk Telekom A.Ş.",
        "isp":        "TurkNet",
        "os":         "Linux 4.x",
        "hostnames":  [f"host-{target_ip.replace('.', '-')}.example.com"],
        "open_ports": [22, 80, 443, 3306],
        "services": [
            {"port": 22,  "transport": "tcp", "product": "OpenSSH", "version": "8.2p1", "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu"},
            {"port": 80,  "transport": "tcp", "product": "nginx",   "version": "1.18.0", "banner": "HTTP/1.1 200 OK Server: nginx"},
            {"port": 443, "transport": "tcp", "product": "nginx",   "version": "1.18.0", "banner": "TLS/1.3 cipher TLS_AES_256_GCM"},
            {"port": 3306,"transport": "tcp", "product": "MySQL",   "version": "8.0.28",  "banner": "8.0.28-MySQL Community Server"}
        ],
        "real_api":       False,
        "simulation_msg": "SHODAN_API_KEY .env dosyasında tanımlı değil. Simüle veri gösterilmektedir."
    })


# ─────────────────────────────────────────────────────────────
# SSL/TLS SERTİFİKA DOĞRULAYICI
# ─────────────────────────────────────────────────────────────
@app.route("/api/security/ssl-check", methods=["POST"])
def ssl_check():
    import ssl as _ssl
    import socket as _sock
    import datetime

    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "Hedef belirtilmedi."}), 400
    target = clean_target_domain(target)

    try:
        ctx = _ssl.create_default_context()
        with _sock.create_connection((target, 443), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=target) as ssock:
                cert    = ssock.getpeercert()
                tls_ver = ssock.version()
                cipher  = ssock.cipher()

        def parse_dt(s):
            try:    return datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
            except: return None

        not_after  = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        expiry_dt  = parse_dt(not_after)
        now        = datetime.datetime.utcnow()
        days_left  = (expiry_dt - now).days if expiry_dt else None

        def flat(tup_list):
            return {k: v for tup in tup_list for k, v in tup}

        issuer  = flat(cert.get("issuer", []))
        subject = flat(cert.get("subject", []))
        sans    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        if days_left is None:         status = "BİLİNMİYOR"
        elif days_left < 0:           status = "SÜRESİ DOLMUŞ"
        elif days_left < 30:          status = "YAKINDA DOLACAK"
        else:                         status = "GEÇERLİ"

        return jsonify({
            "target":       target,
            "status":       status,
            "days_left":    days_left,
            "tls_version":  tls_ver,
            "cipher_suite": cipher[0] if cipher else "Bilinmiyor",
            "not_before":   not_before,
            "not_after":    not_after,
            "issuer_cn":    issuer.get("commonName", "Bilinmiyor"),
            "issuer_org":   issuer.get("organizationName", "Bilinmiyor"),
            "subject_cn":   subject.get("commonName", target),
            "sans":         sans[:10],
        })
    except _ssl.SSLCertVerificationError as e:
        return jsonify({"error": f"SSL Doğrulama Hatası: {str(e)}", "status": "GEÇERSİZ"})
    except Exception as e:
        return jsonify({"error": f"SSL Bağlantı Hatası: {str(e)}", "status": "HATA"}), 500


if __name__ == "__main__":
    print("Sunucu başlatılıyor... Lütfen tarayıcınızdan http://127.0.0.1:5000 adresine gidin.")
    app.run(debug=True, host="0.0.0.0", port=5000)
