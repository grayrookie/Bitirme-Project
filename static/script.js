document.addEventListener('DOMContentLoaded', () => {
    sessionStorage.setItem('greeting_bypassed', 'false');

    let tutorialConfig = {
        main_dashboard: true,
        ping_icmp: true,
        port_scan: true,
        banner_grab: true,
        dos_stress: true,
        osint_leak: true,
        vt_analysis: true,
        sast_code: true,
        session_cookie: true,
        password_strength: true,
        mac_lookup: true,
        hash_generator: true,
        cipher_lab: true
    };


    async function loadTutorialConfig() {
        try {
            const res = await fetch('/api/security/tutorial/status');
            if (res.ok) {
                tutorialConfig = await res.json();
            }
        } catch (e) {
            console.error("Kılavuz yapılandırması yüklenemedi:", e);
        }
    }

    loadTutorialConfig();

    
    // --- YASAL UYARI TAAHHÜT MANTIĞI & AI ASİSTAN OTOMATİK AÇILIŞI ---
    const disclaimerModal = document.getElementById('disclaimer-modal');
    const disclaimerCheck = document.getElementById('disclaimer-check');
    const btnAcceptDisclaimer = document.getElementById('btn-accept-disclaimer');

    function autoOpenChatWidget() {
        // Oturum başına sadece 1 kez otomatik açılması için kontrol (kullanıcıyı rahatsız etmemek adına)
        if (sessionStorage.getItem('chat_auto_opened') === 'true') return;
        
        setTimeout(() => {
            const aiChatWin = document.getElementById('ai-chat-window');
            if (aiChatWin) {
                aiChatWin.style.display = 'flex';
                sessionStorage.setItem('chat_auto_opened', 'true');
            }
        }, 1500);
    }

    // Global istatistik sayaçları
    let stats = {
        targets: 0,
        risks: 0
    };
    
    function updateStats(targetsToAdd = 0, risksToAdd = 0) {
        stats.targets += targetsToAdd;
        stats.risks += risksToAdd;
        
        const targetsEl = document.getElementById('stats-targets');
        const risksEl = document.getElementById('stats-risks');
        
        if (targetsEl) targetsEl.textContent = stats.targets;
        if (risksEl) risksEl.textContent = stats.risks;
    }

    function triggerAiGreeting() {
        // AI greeting disabled to preserve default view states
    }

    function initTutorial() {
        if (window.isFirstOpen && tutorialConfig.main_dashboard) {
            let currentStep = 1;
            const guideOverlay = document.createElement('div');
            guideOverlay.id = 'guide-popup-overlay';
            guideOverlay.className = 'popup-overlay';
            guideOverlay.style.zIndex = '60000';
            guideOverlay.style.display = 'flex';
            
            const steps = [
                {
                    title: "🛡️ Siber Güvenlik İstasyonuna Hoş Geldiniz!",
                    text: "Sol menüyü kullanarak Ağ Analizi, Tehdit İstihbaratı (OSINT) ve Kod Güvenliği (SAST) modülleri arasında asenkron geçiş yapabilirsiniz."
                },
                {
                    title: "🔍 Dinamik Girdi Parametreleri",
                    text: "Taramak istediğiniz hedef IP, URL, alan adı veya e-posta adreslerini merkezdeki veri alanlarına ekleyebilirsiniz."
                },
                {
                    title: "📊 Yapılanlar ve İstatistik Paneli",
                    text: "Sağ üst köşedeki canlı sayaç kartından, o ana kadar yürüttüğünüz analiz sayılarını ve tespit edilen kritik risk durumlarını izleyebilirsiniz."
                }
            ];
            
            const renderStep = () => {
                guideOverlay.innerHTML = `
                    <div class="whoami-popup" style="max-width: 500px; padding: 2rem; border-color: var(--accent-cyan); position: relative; animation: aerodynamicFadeIn 0.3s ease-out;">
                        <div class="whoami-header">
                            <h2 class="whoami-title" style="color: var(--accent-cyan); font-size:1.2rem; display: flex; align-items: center; gap: 0.50rem;"><i class="ti ti-help"></i> Rehber Adım ${currentStep} / 3</h2>
                        </div>
                        <div style="margin: 1.5rem 0; color: #fff; line-height: 1.6;">
                            <h3 style="margin-bottom:0.75rem; font-size: 1.1rem; color: #fff;">${steps[currentStep-1].title}</h3>
                            <p style="color: var(--text-secondary); font-size: 0.95rem;">${steps[currentStep-1].text}</p>
                        </div>
                        <div class="whoami-footer" style="display:flex; justify-content: space-between; align-items:center; border-top: 1px solid rgba(255,255,255,0.05); padding-top:1rem; margin-top:1rem;">
                            <span style="font-size:0.85rem; color:rgba(255,255,255,0.4); font-weight:600;">Adım ${currentStep} / 3</span>
                            <button id="btn-guide-next" class="btn-primary" style="width:auto; padding: 0.6rem 1.5rem;">
                                ${currentStep === 3 ? '<i class="ti ti-check"></i> Bitir' : 'İleri <i class="ti ti-chevron-right"></i>'}
                            </button>
                        </div>
                    </div>
                `;
                
                guideOverlay.querySelector('#btn-guide-next').addEventListener('click', async () => {
                    if (currentStep < 3) {
                        currentStep++;
                        renderStep();
                    } else {
                        guideOverlay.style.display = 'none';
                        document.body.removeChild(guideOverlay);
                        window.isFirstOpen = false;
                        tutorialConfig.main_dashboard = false;
                        try {
                            await fetch('/api/security/tutorial/complete', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ module: 'main_dashboard' })
                            });
                        } catch (e) {
                            console.error("Config save error:", e);
                        }
                    }
                });
            };
            
            document.body.appendChild(guideOverlay);
            renderStep();
        }
    }

    function tutorial_denetle_ve_calistir(moduleName) {
        if (tutorialConfig[moduleName]) {
            let title = "";
            let text = "";
            
            if (moduleName === "main_dashboard") {
                title = "🛡️ Operasyon Kontrol Paneline Hoş Geldiniz!";
                text = "Bu istasyon, atak yüzeyi yönetimi için geliştirilmiş hibrit bir siber güvenlik istemcisidir.\n\nSol menüyü kullanarak araçlar arasında güvenle geçiş yapabilirsiniz.";
            } else if (moduleName === "ping_icmp") {
                title = "🌐 Kılavuz: Ping / ICMP (Ağ Keşfi)";
                text = "• Amacı: Hedef sistemin yerel ağda veya uzak sunucuda aktif (up) olup olmadığını denetler.\n• Entegrasyon: IPinfo kütüphanesiyle asenkron çalışarak hedefin Ülke, Şehir, ISP ve harita koordinatlarını cımbızla çeker.\n• Güvenli Kullanım: Arama çubuğuna ham IP veya alan adı yazarak 'IP SORGULA' butonuna basmanız yeterlidir.";
            } else if (moduleName === "port_scan") {
                title = "🔍 Kılavuz: Port Tarama (Keşif Motoru)";
                text = "• Amacı: Hedef sunucu üzerindeki açık kapıları (Siber Giriş Noktalarını) tespit eder.\n• Teknik Altyapı: Arka planda asenkron soket tarayıcıları çalışır. Sızma testlerinde zafiyet tespiti öncesi en kritik 'Keşif' aşamasıdır.\n• Uyarı: Sistem kilitlenmesini önlemek için işlem bitene kadar terminal ekranından ayrılmayınız.";
            } else if (moduleName === "banner_grab") {
                title = "🎛️ Kılavuz: Derin Port Analizi (Banner)";
                text = "• Amacı: Belirtilen port üzerinde çalışan fiziksel servis tipini ve tam sürüm bilgisini tespit eder.\n• Entegrasyon: Nmap (-sV) mimarisine benzer derin soket okuması yapar.\n• Önemli: Servislerin açık zafiyetlerini (CVE) belirlemede en doğru versiyon bilgisini verir.";
            } else if (moduleName === "dos_stress") {
                title = "⚡ Kılavuz: Web Sunucu Yük & DoS Stres Testi";
                text = "• Amacı: Kendi kontrolünüzdeki sunucuların yüksek trafik altındaki davranışını ve çökme limitlerini ölçer.\n• Çalışma Mantığı: Eş zamanlı asenkron HTTP istekleri göndererek ortalama yanıt süresini ve servis dışı kalma riskini hesaplar.\n• Dikkat: Testleri sadece yetkiniz olan yerel ağ veya test sunucularına uygulayınız.";
            } else if (moduleName === "osint_leak") {
                title = "📬 Kılavuz: Sızıntı Kontrolü (OSINT)";
                text = "• Amacı: Kurumsal e-posta adreslerinin siber yeraltı dünyasında (Dark Web) sızdırılıp sızdırılmadığını denetler.\n• Altyapı: Canlı veri tabanı sorgusu gerçekleştirerek şifre, kullanıcı adı veya kimlik ifşalarını satır satır raporlar.";
            } else if (moduleName === "vt_analysis") {
                title = "🔗 Kılavuz: Güvenli Link & Dosya Analizi";
                text = "• Amacı: Şüpheli URL bağlantılarının veya indirilen dosyaların siber tehdit ve zararlı yazılım durumunu denetler.\n• Çalışma Mantığı: Resmi VirusTotal API'sini sorgulayarak 70+ antivirüs motorunun analiz raporunu bir araya getirir.\n• Kullanım: Bağlantıyı (URL) veya dosya imzasını (MD5/SHA256) girerek taratabilirsiniz.";
            } else if (moduleName === "sast_code") {
                title = "💻 Kılavuz: Güvenli Kod Analizi (SAST)";
                text = "• Amacı: Geliştirilen yazılımların kaynak kodlarındaki siber açıkları (SQL Injection, XSS, RCE) üretim öncesi yakalar.\n• Kullanım: Python kaynak kodunu kutuya yapıştırıp 'KODU ANALİZ ET' butonuyla hızlı tarama gerçekleştirebilirsiniz.";
            } else if (moduleName === "session_cookie") {
                title = "🍪 Kılavuz: Oturum & Çerez Analizi";
                text = "• Amacı: Web sitelerinin çerez (Cookie) politikalarını ve güvenlik bayraklarını (Secure, HttpOnly, SameSite) denetler.\n• Neden Önemli: Eksik bayraklar, oturum çalma (Session Hijacking) ve XSS saldırılarına yol açar.";
            } else if (moduleName === "password_strength") {
                title = "🔑 Kılavuz: Şifre Güç & Kırılma Analizörü";
                text = "• Amacı: Belirlediğiniz şifrenin siber saldırganlar tarafından ne kadar sürede çözülebileceğini (Entropi analiziyle) hesaplar.\n• Zafiyet Sorgusu: Şifrenin daha önce siber sızıntı veritabanlarında ifşa olup olmadığını K-Anonymity gizlilik algoritmasıyla denetler.";
            } else if (moduleName === "mac_lookup") {
                title = "⚙️ Kılavuz: MAC Üretici Bul";
                text = "• Amacı: Ağ kartı fiziksel adresinin (MAC) ilk 3 baytını (OUI) inceleyerek donanımı üreten firmayı (Apple, Cisco, Intel) bulur.\n• Kullanım: Çift nokta veya çizgi ile ayrılmış standart MAC adresini sorgulayabilirsiniz.";
            } else if (moduleName === "hash_generator") {
                title = "🔒 Kılavuz: Kriptografik Hash Oluşturucu";
                text = "• Amacı: Herhangi bir düz metin verisinin tek yönlü kriptografik özetini (MD5, SHA-1, SHA-256) hesaplar.\n• Siber Güvenlikteki Yeri: Dosya bütünlüğü doğrulama (checksum) ve şifrelerin veritabanında güvenli saklanmasında kullanılır.";
            } else if (moduleName === "cipher_lab") {
                title = "🧪 Kılavuz: Kriptografi Laboratuvarı";
                text = "• Amacı: Simetrik (AES, DES) ve Asimetrik (RSA) şifreleme algoritmalarını pratik olarak test etmenizi sağlar.\n• Güvenlik Notu: DES'in zayıf (kırılmış) yapısı ile modern AES ve RSA'nın kırılması imkansız askeri standartları arasındaki farkı gözlemleyebilirsiniz.";
            } else {
                return;
            }

            const guideOverlay = document.createElement('div');
            guideOverlay.id = 'guide-popup-overlay';
            guideOverlay.className = 'popup-overlay';
            guideOverlay.style.zIndex = '60000';
            guideOverlay.style.display = 'flex';
            
            guideOverlay.innerHTML = `
                <div class="whoami-popup" style="max-width: 500px; padding: 2rem; border-color: var(--accent-cyan); position: relative; animation: aerodynamicFadeIn 0.3s ease-out;">
                    <div class="whoami-header">
                        <h2 class="whoami-title" style="color: var(--accent-cyan); font-size:1.15rem; display: flex; align-items: center; gap: 0.50rem;"><i class="ti ti-help"></i> Kılavuz</h2>
                    </div>
                    <div style="margin: 1.5rem 0; color: #fff; line-height: 1.6;">
                        <h3 style="margin-bottom:0.75rem; font-size: 1.05rem; color: #fff;">${title}</h3>
                        <p style="color: var(--text-secondary); font-size: 0.9rem; white-space: pre-wrap;">${text}</p>
                    </div>
                    <div class="whoami-footer" style="display:flex; justify-content: flex-end; align-items:center; border-top: 1px solid rgba(255,255,255,0.05); padding-top:1rem; margin-top:1rem;">
                        <button id="btn-guide-close" class="btn-primary" style="width:auto; padding: 0.6rem 1.5rem;">
                            <i class="ti ti-check"></i> Anladım
                        </button>
                    </div>
                </div>
            `;
            
            guideOverlay.querySelector('#btn-guide-close').addEventListener('click', async () => {
                guideOverlay.style.display = 'none';
                document.body.removeChild(guideOverlay);
                tutorialConfig[moduleName] = false;
                try {
                    await fetch('/api/security/tutorial/complete', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ module: moduleName })
                    });
                } catch (e) {
                    console.error("Config güncelleme hatası:", e);
                }
            });
            
            document.body.appendChild(guideOverlay);
        }
    }

    if (disclaimerModal && disclaimerCheck && btnAcceptDisclaimer) {
        // Her sayfa yenilendiğinde (F5) taahhütname tekrar gösterilsin
        localStorage.removeItem('disclaimer_accepted');
        disclaimerModal.style.display = 'flex';
        disclaimerCheck.checked = false;
        btnAcceptDisclaimer.disabled = true;

        disclaimerCheck.addEventListener('change', () => {
            btnAcceptDisclaimer.disabled = !disclaimerCheck.checked;
        });

        btnAcceptDisclaimer.addEventListener('click', () => {
            localStorage.setItem('disclaimer_accepted', 'true');
            disclaimerModal.style.animation = 'aerodynamicFadeOut 0.5s forwards';
            setTimeout(() => {
                disclaimerModal.style.display = 'none';
                autoOpenChatWidget();
                triggerAiGreeting();
                setTimeout(initTutorial, 200);
            }, 500);
        });
    }

    // --- GELİŞMİŞ AYARLAR PANEL METODLARI ---
    window.toggleAdvancedSettings = function(id) {
        const panel = document.getElementById(id);
        const chevron = document.getElementById(id + '-chevron');
        if (panel.style.display === 'none' || panel.style.display === '') {
            panel.style.display = 'flex';
            if (chevron) chevron.style.transform = 'rotate(180deg)';
        } else {
            panel.style.display = 'none';
            if (chevron) chevron.style.transform = 'rotate(0deg)';
        }
    };

    window.toggleCustomWordlist = function(prefix) {
        const select = document.getElementById(prefix + '-wordlist-type');
        const area = document.getElementById(prefix + '-custom-wordlist-area');
        if (select.value === 'custom') {
            area.style.display = 'flex';
        } else {
            area.style.display = 'none';
        }
    };

    // --- RAPOR DIŞA AKTARMA (EXPORT) METODU ---
    function addExportButtons(containerId, dataset, filenamePrefix, fields) {
        const container = document.getElementById(containerId);
        
        const exportDiv = document.createElement('div');
        exportDiv.className = 'export-container';
        exportDiv.innerHTML = `
            <button class="btn-export" data-format="txt"><i class="ti ti-file-text"></i> TXT Dışa Aktar</button>
            <button class="btn-export" data-format="csv"><i class="ti ti-file-spreadsheet"></i> CSV Dışa Aktar</button>
            <button class="btn-export" data-format="json"><i class="ti ti-file-code"></i> JSON Dışa Aktar</button>
        `;
        
        container.appendChild(exportDiv);
        
        exportDiv.querySelectorAll('.btn-export').forEach(btn => {
            btn.addEventListener('click', () => {
                const format = btn.dataset.format;
                let content = '';
                let mimeType = 'text/plain';
                let extension = 'txt';
                
                const now = new Date().toLocaleString('tr-TR');
                
                if (format === 'json') {
                    content = JSON.stringify({
                        tarih: now,
                        toplam_kayit: dataset.length,
                        veriler: dataset
                    }, null, 4);
                    mimeType = 'application/json';
                    extension = 'json';
                } else if (format === 'csv') {
                    content = '\ufeff'; // UTF-8 BOM to prevent Excel Turkish character issues
                    content += fields.map(f => `"${f.label}"`).join(',') + '\n';
                    dataset.forEach(row => {
                        content += fields.map(f => `"${String(row[f.key] || '').replace(/"/g, '""')}"`).join(',') + '\n';
                    });
                    mimeType = 'text/csv';
                    extension = 'csv';
                } else {
                    content = `CYBER SENTINEL - OPERASYON RAPORU\n`;
                    content += `Oluşturulma Tarihi: ${now}\n`;
                    content += `Toplam Bulunan Kayıt: ${dataset.length}\n`;
                    content += `==================================================\n\n`;
                    
                    dataset.forEach((row, idx) => {
                        content += `[Kayıt #${idx + 1}]\n`;
                        fields.forEach(f => {
                            content += `${f.label}: ${row[f.key] || 'N/A'}\n`;
                        });
                        content += `--------------------------------------------------\n`;
                    });
                    mimeType = 'text/plain';
                    extension = 'txt';
                }
                
                const blob = new Blob([content], { type: `${mimeType};charset=utf-8;` });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${filenamePrefix}_${Date.now()}.${extension}`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });
        });
    }

    // --- GİRİŞ / LOGIN MANTIĞI KALDIRILDI ---
    const btnWhoAmI = document.getElementById('btn-whoami');

    // UI Tabs
    const navItems = document.querySelectorAll('.nav-item');
    const tabContents = document.querySelectorAll('.tab-content');

    function clearAndResetModuleConsole(tabId) {
        // Clear AI buttons that might be showing
        const aiButtons = ['btn-ai-ping', 'btn-ai-port', 'btn-ai-banner', 'btn-ai-stress', 'btn-ai-breach', 'btn-ai-vt', 'btn-ai-sast', 'btn-ai-triage', 'btn-ai-password'];
        aiButtons.forEach(btnId => {
            const btn = document.getElementById(btnId);
            if (btn) btn.style.display = 'none';
        });

        // Hide special charts or panel elements
        const portChartCard = document.getElementById('port-chart-card');
        if (portChartCard) portChartCard.style.display = 'none';
        const stressStatsPanel = document.getElementById('stress-stats-panel');
        if (stressStatsPanel) stressStatsPanel.style.display = 'none';
        const stressChartCard = document.getElementById('stress-chart-card');
        if (stressChartCard) stressChartCard.style.display = 'none';
        const passwordStrengthCard = document.getElementById('password-strength-card');
        if (passwordStrengthCard) passwordStrengthCard.style.display = 'none';


        if (tabId === 'scanner') {
            const pingResults = document.getElementById('ping-results');
            if (pingResults) {
                if (sessionStorage.getItem('greeting_bypassed') === 'true') {
                    pingResults.innerHTML = `
<div style="background: rgba(0, 0, 0, 0.5); padding: 1.25rem; border-left: 4px solid var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; line-height: 1.6; color: #39ff14; white-space: pre-wrap;">[+] Ağ Keşfi (Ping) Modülü Başlatıldı.
[+] Analiz gerçekleştirmek için hedef IP girip 'SONDA GÖNDER' butonuna basınız.</div>`;
                } else {
                    sessionStorage.setItem('greeting_bypassed', 'true');
                }
            }
        } else {
            sessionStorage.setItem('greeting_bypassed', 'true');
        }

        if (tabId === 'ports') {
            const el = document.getElementById('port-results');
            if (el) {
                el.classList.add('empty');
                el.innerHTML = `<div style="background: rgba(0, 0, 0, 0.5); padding: 1.25rem; border-left: 4px solid var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; line-height: 1.6; color: #39ff14; white-space: pre-wrap;">[+] Kritik Port Tarayıcı Modülü Başlatıldı.
[+] Tarama gerçekleştirmek için hedef IP veya site adresi girip 'TARA' butonuna basınız.</div>`;
            }
        }
        if (tabId === 'banner') {
            const el = document.getElementById('banner-results');
            if (el) {
                el.classList.add('empty');
                el.innerHTML = `<div style="background: rgba(0, 0, 0, 0.5); padding: 1.25rem; border-left: 4px solid var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; line-height: 1.6; color: #39ff14; white-space: pre-wrap;">[+] Derin Port Analizi (Banner Grabber) Modülü Başlatıldı.
[+] Servis tespiti için hedef adresi ve port numarasını girip 'ANALİZ ET' butonuna basınız.</div>`;
            }
        }
        if (tabId === 'stress') {
            const el = document.getElementById('stress-results');
            if (el) {
                el.classList.add('empty');
                el.innerHTML = `<div style="background: rgba(0, 0, 0, 0.5); padding: 1.25rem; border-left: 4px solid var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; line-height: 1.6; color: #39ff14; white-space: pre-wrap;">[+] Web Sunucu Yük & DoS Stres Testi Modülü Başlatıldı.
[+] Hedef URL ve istek sayısı belirleyip 'TESTİ BAŞLAT' butonuna basınız.</div>`;
            }
        }
        if (tabId === 'breach') {
            const el = document.getElementById('breach-results');
            if (el) {
                el.classList.add('empty');
                el.innerHTML = `<div style="background: rgba(0, 0, 0, 0.5); padding: 1.25rem; border-left: 4px solid var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; line-height: 1.6; color: #39ff14; white-space: pre-wrap;">[+] Veri Sızıntısı Kontrolü (Breach Checker) Modülü Başlatıldı.
[+] Sorgulanacak e-posta veya şüpheli parolayı yazıp 'KONTROL ET' butonuna basınız.</div>`;
            }
        }
        if (tabId === 'vt') {
            const el = document.getElementById('vt-results');
            if (el) {
                el.classList.add('empty');
                el.innerHTML = `<div style="background: rgba(0, 0, 0, 0.5); padding: 1.25rem; border-left: 4px solid var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; line-height: 1.6; color: #39ff14; white-space: pre-wrap;">[+] Güvenli Link & Dosya Analizi (VirusTotal) Modülü Başlatıldı.
[+] URL, dosya imza hash'i girin veya yerel dosya seçip 'ANALİZ ET' butonuna basınız.</div>`;
            }
        }

        if (tabId === 'sast') {
            const el = document.getElementById('sast-results');
            if (el) {
                el.classList.add('empty');
                el.innerHTML = `<div style="background: rgba(0, 0, 0, 0.5); padding: 1.25rem; border-left: 4px solid var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; line-height: 1.6; color: #39ff14; white-space: pre-wrap;">[+] Statik Güvenli Kod Analizcisi (SAST) Modülü Başlatıldı.
[+] Python kaynak kodunu yapıştırıp 'KODU ANALİZ ET' butonuna basınız.</div>`;
            }
            const triageEl = document.getElementById('ai-triage-results');
            if (triageEl) {
                triageEl.style.display = 'none';
                triageEl.innerHTML = '';
            }
        }
        if (tabId === 'session-cookie') {
            const el = document.getElementById('session-cookie-console');
            if (el) {
                el.value = `[+] Oturum & Çerez Analizi Modülü Başlatıldı.\n[+] Hedef web sitesi adresini girip 'ANALİZ ET' butonuna basınız.`;
            }
        }
        if (tabId === 'password') {
            const el = document.getElementById('password-results');
            if (el) {
                el.classList.add('empty');
                el.innerHTML = `<div style="background: rgba(0, 0, 0, 0.5); padding: 1.25rem; border-left: 4px solid var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; line-height: 1.6; color: #39ff14; white-space: pre-wrap;">[+] Şifre Gücü & Entropi Analizcisi Modülü Başlatıldı.
[+] Test etmek istediğiniz parolayı girip 'ANALİZ ET' butonuna basınız.</div>`;
            }
        }
        if (tabId === 'mac') {
            const el = document.getElementById('mac-results');
            if (el) {
                el.classList.add('empty');
                el.innerHTML = `<div style="background: rgba(0, 0, 0, 0.5); padding: 1.25rem; border-left: 4px solid var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; line-height: 1.6; color: #39ff14; white-space: pre-wrap;">[+] Donanım OUI (MAC) Sorgusu Modülü Başlatıldı.
[+] MAC adresi girip 'DONANIM BUL' butonuna basınız.</div>`;
            }
        }
        if (tabId === 'crypto') {
            const el = document.getElementById('crypto-results');
            if (el) {
                el.classList.add('empty');
                el.innerHTML = `<div style="background: rgba(0, 0, 0, 0.5); padding: 1.25rem; border-left: 4px solid var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; line-height: 1.6; color: #39ff14; white-space: pre-wrap;">[+] Kripto & Hash İşlemleri Modülü Başlatıldı.
[+] Şifrelenecek metin girip 'KRİPTOLA' butonuna basınız.</div>`;
            }
            const el2 = document.getElementById('crack-results');
            if (el2) {
                el2.classList.add('empty');
                el2.innerHTML = '';
            }
        }
    }

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            if (typeof isStationActive !== 'undefined' && !isStationActive) {
                document.getElementById('warn-popup').style.display = 'flex';
                return;
            }
            navItems.forEach(nav => nav.classList.remove('active'));
            tabContents.forEach(tab => tab.classList.remove('active'));
            item.classList.add('active');
            
            const targetTab = item.dataset.tab;
            document.getElementById(targetTab).classList.add('active');
            
            // Clear and reset console of the active tab
            clearAndResetModuleConsole(targetTab);

            // Sayfa bazlı tek seferlik kılavuz tetikleme kontrolü
            const tabToModuleMap = {
                'scanner': 'ping_icmp',
                'ports': 'port_scan',
                'banner': 'banner_grab',
                'stress': 'dos_stress',
                'breach': 'osint_leak',
                'vt': 'vt_analysis',
                'sast': 'sast_code',
                'session-cookie': 'session_cookie',
                'password': 'password_strength',
                'mac': 'mac_lookup',
                'crypto': 'hash_generator',
                'cipherlab': 'cipher_lab'
            };
            const mappedModule = tabToModuleMap[targetTab];
            if (mappedModule) {
                tutorial_denetle_ve_calistir(mappedModule);
            }

        });
    });


    // Helper functions
    function setLoading(btnId, loading) {
        const btn = document.getElementById(btnId);
        if (loading) {
            btn.dataset.text = btn.innerHTML;
            btn.innerHTML = '<span class="loader"></span> İŞLENİYOR...';
            btn.disabled = true;
        } else {
            btn.innerHTML = btn.dataset.text;
            btn.disabled = false;
        }
    }

    function addLog(containerId, message, type = 'info', isHtml = false) {
        const c = document.getElementById(containerId);
        c.classList.remove('empty');
        const d = document.createElement('div');
        if(!isHtml) {
            d.className = `log-line`;
            let icon = 'ti-info-circle status-info';
            if (type === 'success') icon = 'ti-circle-check status-up';
            if (type === 'error') icon = 'ti-circle-x status-down';
            d.innerHTML = `<i class="ti ${icon}"></i> <span>${message}</span>`;
        } else d.innerHTML = message;
        c.appendChild(d);
        c.scrollTop = c.scrollHeight;
    }

    function clearBox(id) { document.getElementById(id).innerHTML = ''; }

    // API Helper
    async function postApi(url, target, btnId, resId, cb) {
        if(!target) return;
        clearBox(resId);
        setLoading(btnId, true);
        try {
            const req = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(target)
            });
            const data = await req.json();
            if(data.error) throw new Error(data.error);
            cb(data);
        } catch (err) {
            addLog(resId, `[Hata]: ${err.message}`, 'error');
        } finally {
            setLoading(btnId, false);
        }
    }

    // --- PORT CHART DRAWING FUNCTION ---
    function drawDoughnutChart(canvasId, openCount, closedCount) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        const total = openCount + closedCount;
        if (total === 0) return;
        
        const centerX = canvas.width / 2;
        const centerY = canvas.height / 2;
        const radius = Math.min(centerX, centerY) - 10;
        const thickness = 14;
        
        const openAngle = (openCount / total) * 2 * Math.PI;
        
        // Draw background (Closed Ports / Unknown)
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
        ctx.strokeStyle = 'rgba(255, 0, 60, 0.15)';
        ctx.lineWidth = thickness;
        ctx.stroke();
        
        // Draw Open Ports sector (glowing cyan)
        if (openCount > 0) {
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, -Math.PI / 2, -Math.PI / 2 + openAngle);
            ctx.strokeStyle = '#00f0ff';
            ctx.lineWidth = thickness;
            ctx.shadowBlur = 10;
            ctx.shadowColor = '#00f0ff';
            ctx.stroke();
            ctx.shadowBlur = 0; // Reset
        }
        
        // Draw Closed Ports sector remaining
        if (closedCount > 0) {
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, -Math.PI / 2 + openAngle, 1.5 * Math.PI);
            ctx.strokeStyle = '#ff003c';
            ctx.lineWidth = thickness;
            ctx.shadowBlur = 8;
            ctx.shadowColor = '#ff003c';
            ctx.stroke();
            ctx.shadowBlur = 0;
        }
        
        // Center text
        ctx.fillStyle = '#ffffff';
        ctx.font = '800 1.2rem "Inter", sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(`${Math.round((openCount/total)*100)}%`, centerX, centerY - 6);
        
        ctx.fillStyle = 'var(--text-secondary)';
        ctx.font = '600 0.6rem "JetBrains Mono", monospace';
        ctx.fillText('AÇIK ORAN', centerX, centerY + 14);
    }

    // --- LATENCY BAR CHART FOR STRESSTEST ---
    function drawLatencyBarChart(canvasId, latencies) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        if (!latencies || latencies.length === 0) return;
        
        // Render simple bar graph representing response times
        const maxVal = Math.max(...latencies, 100);
        const padding = 15;
        const width = canvas.width - 2 * padding;
        const height = canvas.height - 2 * padding;
        const barWidth = width / latencies.length;
        
        // Draw grid/background lines
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = padding + (height / 4) * i;
            ctx.beginPath();
            ctx.moveTo(padding, y);
            ctx.lineTo(canvas.width - padding, y);
            ctx.stroke();
        }
        
        // Draw latency bars
        latencies.forEach((lat, index) => {
            const barHeight = (lat / maxVal) * height;
            const x = padding + index * barWidth;
            const y = canvas.height - padding - barHeight;
            
            // Color based on latency severity
            let color = 'rgba(0, 240, 255, 0.65)'; // Cyan
            if (lat > 500.0) {
                color = 'rgba(255, 0, 60, 0.85)'; // Red
            } else if (lat > 300.0) {
                color = 'rgba(234, 179, 8, 0.75)'; // Yellow
            }
            
            ctx.fillStyle = color;
            ctx.fillRect(x, y, Math.max(1, barWidth - 1), barHeight);
        });

        // Write max latency label
        ctx.fillStyle = 'var(--text-secondary)';
        ctx.font = '700 0.55rem "JetBrains Mono", monospace';
        ctx.fillText(`MAKS: ${Math.round(maxVal)}ms`, padding, padding - 5);
    }


    // 1. Ping
    document.getElementById('btn-ping').addEventListener('click', () => {
        const targetVal = document.getElementById('ping-target').value.trim();
        if(!targetVal) return;
        
        postApi('/api/scan/ping', {target: targetVal}, 'btn-ping', 'ping-results', (data) => {
            updateStats(1, data.alive ? 0 : 1);
            if (data.output) {
                addLog('ping-results', `<div style="background:rgba(0,0,0,0.5); padding:1rem; border-left:4px solid var(--accent-cyan); white-space:pre-wrap; font-family:'JetBrains Mono',monospace; font-size:0.88rem; line-height:1.6; margin-top:0.5rem; color:#e0e0e0;">${data.output}</div>`, 'none', true);
            }
            if (data.alive) {
                addLog('ping-results', `Hedef ${data.target} ayakta (ALIVE).`, 'success');
            } else {
                addLog('ping-results', `Hedef ${data.target} ulaşılamaz (DOWN) veya ICMP paketleri engellendi.`, 'error');
            }
            document.getElementById('btn-ai-ping').style.display = 'inline-flex';
        });
    });

    // 2. Port
    document.getElementById('btn-portscan').addEventListener('click', () => {
        const targetVal = document.getElementById('port-target').value.trim();
        if(!targetVal) return;
        
        document.getElementById('port-chart-card').style.display = 'none';
        
        postApi('/api/scan/ports', {target: targetVal}, 'btn-portscan', 'port-results', (data) => {
            updateStats(1, data.open_ports ? data.open_ports.length : 0);
            if (data.open_ports.length === 0) {
                return addLog('port-results', 'Açık port bulunamadı.', 'info');
            }
            
            addLog('port-results', `<b>${data.open_ports.length} Açık Port Bulundu:</b>`, 'success', true);
            data.open_ports.forEach(p => {
                addLog('port-results', `<div class="port-card"><div><div class="port-number">PORT ${p.port}</div><div class="port-service">${p.service}</div></div><div class="status-open">AÇIK <i class="ti ti-lock-open"></i></div></div>`, 'none', true);
            });
            
            // Draw chart
            const openCount = data.open_ports.length;
            const totalCommon = 16; // Number of ports in app.py's COMMON_PORTS
            const closedCount = Math.max(0, totalCommon - openCount);
            
            document.getElementById('port-chart-card').style.display = 'flex';
            drawDoughnutChart('port-chart', openCount, closedCount);
            
            addExportButtons('port-results', data.open_ports, 'port_tarama_raporu', [
                { label: 'Port Numarası', key: 'port' },
                { label: 'Servis / Protokol', key: 'service' },
                { label: 'Durum', key: 'status' }
            ]);
            document.getElementById('btn-ai-port').style.display = 'inline-flex';
        });
    });

    // 3. Banner
    document.getElementById('btn-banner').addEventListener('click', async () => {
        const t = document.getElementById('banner-target').value.trim();
        const p = document.getElementById('banner-port').value.trim();
        if (!t || !p) return;

        const resId = 'banner-results';
        clearBox(resId);
        setLoading('btn-banner', true);

        try {
            const req = await fetch('/api/scan/banner', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: t, port: p })
            });
            const data = await req.json();

            if (data.error) {
                // Hata mesajını göster
                addLog(resId, `[Hata]: ${data.error}`, 'error');

                // Eğer ek bilgi notu varsa (örn. ConnectionRefusedError), altında göster
                if (data.note) {
                    addLog(resId, `
                        <div style="margin-top:0.75rem; padding:0.85rem 1rem; border-radius:0.75rem;
                            background:rgba(0,240,255,0.04); border:1px solid rgba(0,240,255,0.15);
                            color:var(--text-secondary); font-size:0.83rem; line-height:1.6;">
                            <span style="color:var(--accent-cyan); font-weight:700; display:block; margin-bottom:0.3rem;">
                                <i class="ti ti-info-circle"></i> Bilgi Notu
                            </span>
                            ${data.note}
                        </div>`, 'none', true);
                }
            } else if (data.is_firewall) {
                updateStats(1, 1);
                // Firewall/Timeout → özel uyarı kartı
                addLog(resId, `[PORT ${data.port}] Bağlantı Analizi Sonucu:`, 'info');
                addLog(resId, `
                    <div style="margin-top:0.5rem; padding:1.25rem; border-radius:1rem;
                        background:rgba(234,179,8,0.04); border:1px solid rgba(234,179,8,0.25);
                        font-family:'JetBrains Mono',monospace; font-size:0.86rem; line-height:1.8; white-space:pre-wrap;">
                        <div style="color:#eab308; font-weight:800; font-size:0.9rem; margin-bottom:0.75rem; display:flex; align-items:center; gap:0.5rem;">
                            <i class="ti ti-shield-check"></i> GÜVENLIK DUVANINDAN ENGELLENDİ — FİREWALL ANALİZ RAPORU
                        </div>
                        <span style="color:#fff;">${data.banner}</span>
                    </div>`, 'none', true);
                document.getElementById('btn-ai-banner').style.display = 'inline-flex';
            } else {
                updateStats(1, 0);
                addLog(resId, `[PORT ${data.port}] Hedef Servis Yanıtı:`, 'info');
                addLog(resId, `<div style="background:rgba(0,0,0,0.5); padding:1rem; border-left:4px solid var(--accent-magenta); white-space:pre-wrap; font-family:'JetBrains Mono',monospace; font-size:0.88rem; line-height:1.6;">${data.banner}</div>`, 'none', true);
                document.getElementById('btn-ai-banner').style.display = 'inline-flex';
            }
        } catch (err) {
            addLog(resId, `[Hata]: ${err.message}`, 'error');
        } finally {
            setLoading('btn-banner', false);
        }
    });

    // 9. MAC
    document.getElementById('btn-mac').addEventListener('click', () => {
        postApi('/api/scan/mac', {target: document.getElementById('mac-target').value.trim()}, 'btn-mac', 'mac-results', (data) => {
            addLog('mac-results', `Üretici Bilgisi: <br><strong style="font-size:1.4em; color:var(--accent-cyan)">${data.vendor}</strong>`, 'none', true);
        });
    });

    // 10. Crypto Hash Creator
    document.getElementById('btn-crypto').addEventListener('click', () => {
        postApi('/api/crypto/hash', {target: document.getElementById('crypto-target').value.trim()}, 'btn-crypto', 'crypto-results', (data) => {
            let h = `<div style="display:flex; flex-direction:column; gap:0.5rem">
                <div style="background:rgba(255,255,255,0.05); padding:1rem; border-radius:0.5rem"><b>MD5:</b> ${data.md5}</div>
                <div style="background:rgba(255,255,255,0.05); padding:1rem; border-radius:0.5rem"><b>SHA1:</b> ${data.sha1}</div>
                <div style="background:rgba(255,255,255,0.05); padding:1rem; border-radius:0.5rem"><b>SHA256:</b> ${data.sha256}</div>
            </div>`;
            addLog('crypto-results', h, 'none', true);
        });
    });

    // 11. Crypto Hash Cracker
    document.getElementById('btn-crack').addEventListener('click', () => {
        const type = document.getElementById('crack-type').value;
        const target = document.getElementById('crack-target').value.trim();
        if(!target) return;
        
        postApi('/api/crypto/crack', {target: target, type: type}, 'btn-crack', 'crack-results', (data) => {
            updateStats(1, data.cracked ? 1 : 0);
            if(data.cracked) {
                addLog('crack-results', `BAŞARILI: Kırılan Şifre: <br><strong style="font-size:1.5em; color:var(--accent-cyan); letter-spacing: 2px;">${data.password}</strong>`, 'none', true);
                addLog('crack-results', `Kullanılan Yöntem: ${data.method}`, 'success');
            } else {
                addLog('crack-results', data.error, 'error');
            }
        });
    });

    // 12. Email Sızıntı Kontrolü (Breach Checker)
    const breachTypeSelect = document.getElementById('breach-type');
    const breachTargetInput = document.getElementById('breach-target');
    
    if (breachTypeSelect && breachTargetInput) {
        breachTypeSelect.addEventListener('change', () => {
            if (breachTypeSelect.value === 'email') {
                breachTargetInput.placeholder = 'Örn: eposta@gmail.com';
                breachTargetInput.type = 'email';
            } else {
                breachTargetInput.placeholder = 'Örn: admin12345';
                breachTargetInput.type = 'text';
            }
        });
    }

    document.getElementById('btn-breach').addEventListener('click', () => {
        const targetVal = document.getElementById('breach-target').value.trim();
        const targetType = document.getElementById('breach-type') ? document.getElementById('breach-type').value : 'email';
        if (!targetVal) return;
        
        const btnAiBreach = document.getElementById('btn-ai-breach');
        if (btnAiBreach) btnAiBreach.style.display = 'none';
        
        if (targetType === 'email') {
            const emailRegex = /^[\w\.-]+@[\w\.-]+\.\w+$/;
            if (!emailRegex.test(targetVal)) {
                const resultsContainer = document.getElementById('breach-results');
                if (resultsContainer) {
                    resultsContainer.innerHTML = '';
                    resultsContainer.classList.remove('empty');
                }
                addLog('breach-results', `<div style="background:rgba(0,0,0,0.5); padding:1rem; border-left:4px solid var(--accent-red); white-space:pre-wrap; font-family:'JetBrains Mono',monospace; font-size:0.88rem; line-height:1.6; color:#f87171;">[-] Hata: Geçerli bir e-posta formatı girmediniz! (Örn: ad@domain.com)</div>`, 'none', true);
                return;
            }
        }
        
        postApi('/api/osint/breach', {type: targetType, target: targetVal}, 'btn-breach', 'breach-results', (data) => {
            updateStats(1, (data.breached && data.breaches) ? data.breaches.length : 0);
            if (data.error) {
                if (data.output) {
                    addLog('breach-results', `<div style="background:rgba(0,0,0,0.5); padding:1rem; border-left:4px solid var(--accent-red); white-space:pre-wrap; font-family:'JetBrains Mono',monospace; font-size:0.88rem; line-height:1.6; color:#f87171;">${data.output}</div>`, 'none', true);
                }
                return addLog('breach-results', data.error, 'error');
            }
            
            if (data.output) {
                addLog('breach-results', `<div style="background:rgba(0,0,0,0.5); padding:1rem; border-left:4px solid var(--accent-magenta); white-space:pre-wrap; font-family:'JetBrains Mono',monospace; font-size:0.88rem; line-height:1.6; margin-bottom:1rem; color:#e0e0e0;">${data.output}</div>`, 'none', true);
            }
            
            if (!data.breached) {
                addLog('breach-results', `<div style="padding:1rem; border-radius:0.75rem; border: 1px solid var(--accent-green); background:rgba(16,185,129,0.05); color:#ffffff;"><i class="fa-solid fa-circle-check status-up"></i> ${data.message}</div>`, 'none', true);
                return;
            }
            
            let simBadge = data.simulated ? ' <span style="font-size:0.7em; padding:0.1rem 0.4rem; background:rgba(239,68,68,0.2); border:1px solid var(--accent-red); border-radius:4px; color:var(--accent-red)">SİMÜLE EDİLDİ</span>' : '';
            const titleText = targetType === 'email' ? 'UYARI: Bu E-posta Adresi Sızdırılmış!' : 'UYARI: Bu Parola Sızdırılmış!';
            addLog('breach-results', `<strong class="status-down" style="font-size:1.1rem;"><i class="fa-solid fa-triangle-exclamation"></i> ${titleText}${simBadge}</strong>`, 'none', true);
            addLog('breach-results', `Aşağıdaki veri tabanı ihlallerinde bu hedefe ait kayıtlar tespit edildi:`, 'info');
            
            let tableHtml = `
                <div class="cyber-table-container">
                    <table class="cyber-table">
                        <thead>
                            <tr>
                                <th>Sızıntı / Platform</th>
                                <th>Tarih</th>
                                <th>Sızıntı Detayı</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            data.breaches.forEach(b => {
                tableHtml += `
                    <tr>
                        <td style="color: var(--accent-magenta); font-weight:bold;">${b.name}</td>
                        <td>${b.date}</td>
                        <td style="color: var(--text-secondary); white-space:normal; max-width:300px; overflow:hidden; text-overflow:ellipsis;">${b.details}</td>
                    </tr>
                `;
            });
            
            tableHtml += `
                        </tbody>
                    </table>
                </div>
            `;
            
            addLog('breach-results', tableHtml, 'none', true);
            
            addExportButtons('breach-results', data.breaches, 'sizinti_raporu', [
                { label: 'Platform / Kaynak', key: 'name' },
                { label: 'Tarih', key: 'date' },
                { label: 'Detaylar', key: 'details' }
            ]);
            document.getElementById('btn-ai-breach').style.display = 'inline-flex';
        });
    });

    // 13. Güvenli Link Analizi (VirusTotal)
    let vtSelectedFilePath = "";

    const btnVtSelectFile = document.getElementById('btn-vt-select-file');
    const btnVtClearFile = document.getElementById('btn-vt-clear-file');
    const vtSelectDropdown = document.getElementById('vt-select-dropdown');
    const vtSelectedFileContainer = document.getElementById('vt-selected-file-container');
    const vtSelectedFileName = document.getElementById('vt-selected-file-name');
    const vtTargetInput = document.getElementById('vt-target');

    // UI Temizleme Mekanizması (UI Reset)
    function vt_ui_temizle() {
        vtSelectedFilePath = "";
        if (vtTargetInput) vtTargetInput.value = "";
        if (vtSelectedFileContainer) vtSelectedFileContainer.style.display = 'none';
        if (vtSelectedFileName) vtSelectedFileName.textContent = "";
        
        const vtResults = document.getElementById('vt-results');
        if (vtResults) {
            vtResults.innerHTML = '';
            vtResults.classList.add('empty');
        }
        
        const btnAiVt = document.getElementById('btn-ai-vt');
        if (btnAiVt) btnAiVt.style.display = 'none';

        console.log("[+] UI Otomatik Temizleme Tetiklendi: Eski analiz verileri sıfırlandı.");
    }

    if (btnVtSelectFile && vtSelectDropdown) {
        // Dropdown aç/kapat
        btnVtSelectFile.addEventListener('click', (e) => {
            e.stopPropagation();
            vtSelectDropdown.style.display = vtSelectDropdown.style.display === 'block' ? 'none' : 'block';
        });

        // Dropdown dışına tıklandığında menüyü kapat
        document.addEventListener('click', () => {
            vtSelectDropdown.style.display = 'none';
        });

        // Dropdown içindeki elemanların hover ve click aksiyonları
        vtSelectDropdown.querySelectorAll('.dropdown-item').forEach(item => {
            item.addEventListener('mouseenter', () => item.style.background = 'rgba(255, 255, 255, 0.08)');
            item.addEventListener('mouseleave', () => item.style.background = 'none');
            
            item.addEventListener('click', async (e) => {
                e.stopPropagation();
                vtSelectDropdown.style.display = 'none';
                const mode = item.dataset.mode;
                
                setLoading('btn-vt-select-file', true);
                try {
                    const req = await fetch('/api/osint/select-file', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ mode: mode })
                    });
                    const data = await req.json();
                    if (data.success && data.file_path) {
                        vtTargetInput.value = '';
                        vtSelectedFilePath = data.file_path;
                        vtTargetInput.value = data.file_path;
                        
                        const icon = data.is_directory ? '<i class="ti ti-folder"></i> ' : '<i class="ti ti-file-text"></i> ';
                        vtSelectedFileName.innerHTML = icon + data.filename;
                        vtSelectedFileContainer.style.display = 'inline-flex';
                    }
                } catch (err) {
                    console.error("Seçim penceresi açılamadı: ", err);
                } finally {
                    setLoading('btn-vt-select-file', false);
                }
            });
        });
    }

    if (btnVtClearFile) {
        btnVtClearFile.addEventListener('click', () => {
            vt_ui_temizle();
        });
    }

    if (vtTargetInput) {
        vtTargetInput.addEventListener('input', () => {
            if (vtTargetInput.value.trim() === "") {
                vt_ui_temizle();
            } else if (vtTargetInput.value.trim() !== vtSelectedFilePath) {
                vtSelectedFilePath = "";
                if (vtSelectedFileContainer) vtSelectedFileContainer.style.display = 'none';
                if (vtSelectedFileName) vtSelectedFileName.textContent = "";
            }
        });
    }

    document.getElementById('btn-vt').addEventListener('click', () => {
        const targetVal = vtTargetInput.value.trim();
        if (!targetVal && !vtSelectedFilePath) return;
        
        postApi('/api/osint/virustotal', {target: targetVal, file_path: vtSelectedFilePath}, 'btn-vt', 'vt-results', (data) => {
            updateStats(1, (data.positives && data.positives > 0) ? data.positives : 0);
            if (data.error || !data.success) {
                if (data.output) {
                    addLog('vt-results', `<div style="background:rgba(0,0,0,0.5); padding:1rem; border-left:4px solid var(--accent-red); white-space:pre-wrap; font-family:'JetBrains Mono',monospace; font-size:0.88rem; line-height:1.6; margin-top:0.5rem; margin-bottom:1rem; color:#f87171;">${data.output}</div>`, 'none', true);
                }
                return addLog('vt-results', data.error || 'Tarama başarısız oldu.', 'error');
            }
            
            const isMalicious = data.positives > 0;
            const statusColor = isMalicious ? 'var(--accent-red)' : 'var(--accent-green)';
            const statusIcon = isMalicious ? 'fa-triangle-exclamation' : 'fa-circle-check';
            const statusText = isMalicious ? 'ZARARLI / ŞÜPHELİ' : 'TEMİZ / GÜVENLİ';
            
            let simText = data.simulation_msg ? `<div style="font-size:0.8rem; color:var(--accent-magenta); margin-bottom:1rem;"><i class="fa-solid fa-circle-info"></i> ${data.simulation_msg}</div>` : '';
            
            let headerHtml = `
                <div style="padding:1.25rem; border-radius:1rem; border: 1px solid ${statusColor}; background: rgba(255,255,255,0.02); margin-bottom:1rem;">
                    ${simText}
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="font-size:0.8rem; color:var(--text-secondary); text-transform:uppercase;">Hedef ${data.type}</div>
                            <div style="font-size:1.15rem; font-weight:800; color:#fff; word-break:break-all;">${data.target}</div>
                        </div>
                        <div style="text-align:right;">
                            <span style="color:${statusColor}; font-weight:800; font-size:1.1rem; display:flex; align-items:center; gap:0.4rem; justify-content:flex-end;">
                                <i class="fa-solid ${statusIcon}"></i> ${statusText}
                            </span>
                            <span style="font-family:'JetBrains Mono'; font-size:0.85rem; color:var(--text-secondary);">Algılama Oranı: ${data.positives} / ${data.total}</span>
                        </div>
                    </div>
                </div>
            `;
            addLog('vt-results', headerHtml, 'none', true);
            
            if (data.output) {
                addLog('vt-results', `<div style="background:rgba(0,0,0,0.5); padding:1rem; border-left:4px solid var(--accent-magenta); white-space:pre-wrap; font-family:'JetBrains Mono',monospace; font-size:0.88rem; line-height:1.6; margin-top:0.5rem; margin-bottom:1.25rem; color:#e0e0e0;">${data.output}</div>`, 'none', true);
            }
            
            let tableHtml = `
                <div class="cyber-table-container">
                    <table class="cyber-table">
                        <thead>
                            <tr>
                                <th>Güvenlik Motoru</th>
                                <th>Sınıflandırma</th>
                                <th>Tarama Sonucu</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            data.engines.forEach(e => {
                let catClass = 'status-info';
                let iconHtml = '<i class="fa-solid fa-circle-question"></i>';
                
                if (e.category === 'malicious') {
                    catClass = 'status-down';
                    iconHtml = '<i class="fa-solid fa-shield-virus"></i>';
                } else if (e.category === 'suspicious') {
                    catClass = 'status-down';
                    iconHtml = '<i class="fa-solid fa-triangle-exclamation"></i>';
                } else if (e.category === 'harmless' || e.category === 'clean') {
                    catClass = 'status-up';
                    iconHtml = '<i class="fa-solid fa-circle-check"></i>';
                }
                
                let cleanResult = e.result.replace(/[🚨🟢⚠️]/g, '').trim();
                
                tableHtml += `
                    <tr>
                        <td style="font-weight:bold; color:#fff;">${e.engine}</td>
                        <td>${e.category.toUpperCase()}</td>
                        <td><span class="${catClass}" style="display:inline-flex; align-items:center; gap:0.4rem;">${iconHtml}${cleanResult}</span></td>
                    </tr>
                `;
            });
            
            tableHtml += `
                        </tbody>
                    </table>
                </div>
            `;
            
            addLog('vt-results', tableHtml, 'none', true);
            
            addExportButtons('vt-results', data.engines, 'virustotal_analiz_raporu', [
                { label: 'Motor Adı', key: 'engine' },
                { label: 'Kategori', key: 'category' },
                { label: 'Sonuç', key: 'result' }
            ]);
            document.getElementById('btn-ai-vt').style.display = 'inline-flex';
        });
    });




    // 14. Güvenli Kod Analizi (SAST)
    document.getElementById('btn-sast').addEventListener('click', () => {
        const codeVal = document.getElementById('sast-code').value;
        if (!codeVal.trim()) return;
        
        postApi('/api/security/code-scan', {target: codeVal}, 'btn-sast', 'sast-results', (data) => {
            const risks = data.issues ? data.issues.length : 0;
            updateStats(1, risks);
            if (data.issues.length === 0) {
                addLog('sast-results', `<div style="padding:1.25rem; border-radius:1rem; border: 1px solid var(--accent-green); background:rgba(16,185,129,0.05); color:#fff;"><i class="fa-solid fa-circle-check status-up"></i> <strong>Tebrikler:</strong> Statik kod analizinde herhangi bir güvenlik açığı veya zayıflık tespit edilemedi. Kod kurallara uygun görünüyor.</div>`, 'none', true);
                return;
            }
            
            addLog('sast-results', `<strong class="status-down" style="font-size:1.1rem;"><i class="fa-solid fa-bug"></i> Analiz Tamamlandı: ${data.issues.length} Olası Zafiyet Tespit Edildi</strong>`, 'none', true);
            
            let tableHtml = `
                <div class="cyber-table-container">
                    <table class="cyber-table">
                        <thead>
                            <tr>
                                <th>Zafiyet Seviyesi</th>
                                <th>Satır</th>
                                <th>Bulgu Türü</th>
                                <th>Güvensiz Kod Bloğu</th>
                                <th>Açıklama / Analiz</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            data.issues.forEach(i => {
                let sevColor = 'var(--accent-magenta)';
                if (i.severity === 'ORTA') sevColor = '#eab308';
                if (i.severity === 'DÜŞÜK') sevColor = 'var(--accent-blue)';
                
                tableHtml += `
                    <tr>
                        <td><span style="color:${sevColor}; font-weight:800; border: 1px solid ${sevColor}; padding:0.15rem 0.5rem; border-radius:0.25rem; font-size:0.75rem;">${i.severity}</span></td>
                        <td style="font-family:'JetBrains Mono'; font-weight:bold;">L${i.line}</td>
                        <td style="color:#fff; font-weight:600;">${i.issue}</td>
                        <td style="font-family:'JetBrains Mono'; color:#f43f5e; font-size:0.82rem; background:rgba(0,0,0,0.3); padding:0.3rem 0.5rem; border-radius:0.25rem; border:1px solid rgba(255,255,255,0.02);">${i.code}</td>
                        <td style="color:var(--text-secondary); white-space:normal; max-width:280px; font-size:0.82rem; line-height:1.4;">${i.details}</td>
                    </tr>
                `;
            });
            
            tableHtml += `
                        </tbody>
                    </table>
                </div>
            `;
            
            addLog('sast-results', tableHtml, 'none', true);
            
            addExportButtons('sast-results', data.issues, 'sast_kod_analiz_raporu', [
                { label: 'Risk Derecesi', key: 'severity' },
                { label: 'Satır No', key: 'line' },
                { label: 'Zafiyet Türü', key: 'issue' },
                { label: 'Kod Parçası', key: 'code' },
                { label: 'Açıklama Detayı', key: 'details' }
            ]);
            document.getElementById('btn-ai-sast').style.display = 'inline-flex';
            document.getElementById('btn-ai-triage').style.display = 'inline-flex';
        });
    });

    // 15. Şifre Güç Kontrolü
    document.getElementById('btn-password').addEventListener('click', () => {
        const targetVal = document.getElementById('password-target').value;
        if (!targetVal) return;
        
        postApi('/api/security/password-check', {target: targetVal}, 'btn-password', 'password-results', (data) => {
            updateStats(1, (data.is_common || data.level < 3) ? 1 : 0);
            const card = document.getElementById('password-strength-card');
            const bar = document.getElementById('password-strength-bar');
            const label = document.getElementById('password-strength-label');
            
            card.style.display = 'block';
            label.textContent = data.strength;
            label.style.color = data.color;
            
            const pct = data.level * 25;
            bar.style.width = `${pct}%`;
            bar.style.backgroundColor = data.color;
            bar.style.color = data.color;
            
            let commonWarning = data.is_common 
                ? `<div style="padding:0.75rem 1rem; margin-bottom:1rem; border-radius:0.5rem; background:rgba(239,68,68,0.1); border:1px solid var(--accent-red); color:#fff; font-size:0.85rem;"><i class="fa-solid fa-triangle-exclamation status-down"></i> <strong>Kritik Uyarı:</strong> Bu şifre en yaygın şifre listesindedir. Saniyeler içinde kırılabilir!</div>` 
                : '';
                
            let h = `
                ${commonWarning}
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:1rem; font-family:'JetBrains Mono', monospace; font-size:0.88rem;">
                    <div style="background:rgba(255,255,255,0.02); padding:1rem; border-radius:0.75rem; border:1px solid rgba(255,255,255,0.03);">
                        <div style="color:var(--text-secondary); font-size:0.75rem; text-transform:uppercase; margin-bottom:0.25rem;">Bilgi Entropisi</div>
                        <div style="font-size:1.4rem; font-weight:800; color:var(--accent-cyan);">${data.entropy} Bits</div>
                    </div>
                    <div style="background:rgba(255,255,255,0.02); padding:1rem; border-radius:0.75rem; border:1px solid rgba(255,255,255,0.03);">
                        <div style="color:var(--text-secondary); font-size:0.75rem; text-transform:uppercase; margin-bottom:0.25rem;">Brute-Force Süresi</div>
                        <div style="font-size:1.1rem; font-weight:800; color:#fff; padding-top:0.25rem;">${data.crack_time}</div>
                    </div>
                    <div style="background:rgba(255,255,255,0.02); padding:1rem; border-radius:0.75rem; border:1px solid rgba(255,255,255,0.03);">
                        <div style="color:var(--text-secondary); font-size:0.75rem; text-transform:uppercase; margin-bottom:0.25rem;">Karakter Havuzu (Pool)</div>
                        <div style="font-size:1.4rem; font-weight:800; color:#fff;">${data.character_pool} Karakter</div>
                    </div>
                    <div style="background:rgba(255,255,255,0.02); padding:1rem; border-radius:0.75rem; border:1px solid rgba(255,255,255,0.03);">
                        <div style="color:var(--text-secondary); font-size:0.75rem; text-transform:uppercase; margin-bottom:0.25rem;">Şifre Uzunluğu</div>
                        <div style="font-size:1.4rem; font-weight:800; color:#fff;">${data.length} Karakter</div>
                    </div>
                </div>
            `;
            
            addLog('password-results', h, 'none', true);
            
            addExportButtons('password-results', [data], 'sifre_analiz_raporu', [
                { label: 'Şifre Gücü', key: 'strength' },
                { label: 'Entropi (Bits)', key: 'entropy' },
                { label: 'Tahmini Kırılma Süresi', key: 'crack_time' },
                { label: 'Havuz Boyutu', key: 'character_pool' },
                { label: 'Uzunluk', key: 'length' }
            ]);
            document.getElementById('btn-ai-password').style.display = 'inline-flex';
        });
    });

    // --- WARN POPUP LOGIC ---
    const warnPopup = document.createElement('div');
    warnPopup.id = 'warn-popup';
    warnPopup.className = 'popup-overlay';
    warnPopup.style.display = 'none';
    warnPopup.innerHTML = `
        <div style="background: rgba(15, 15, 20, 0.95); padding: 3rem; border-radius: 1.5rem; text-align: center; border: 1px solid var(--accent-magenta); box-shadow: 0 0 40px rgba(255, 0, 60, 0.3);">
            <i class="ti ti-alert-triangle" style="font-size: 3.5rem; color: var(--accent-magenta); margin-bottom: 1.5rem; filter: drop-shadow(0 0 10px rgba(255,0,60,0.5));"></i>
            <h2 style="color: var(--text-primary); margin-bottom: 2rem; font-size: 1.8rem; letter-spacing: 0.05em; text-transform: uppercase;">Lütfen İstasyonu Aktif Edin</h2>
            <div style="display: flex; gap: 1rem; justify-content: center;">
                <button id="btn-popup-close" class="btn-primary" style="background: rgba(255,255,255,0.05); color: #fff; box-shadow: none;">Kapat</button>
                <button id="btn-popup-activate" class="btn-primary" style="background: linear-gradient(135deg, var(--accent-green), #059669); color: #fff;">İstasyonu Aktif Et</button>
            </div>
        </div>
    `;
    document.body.appendChild(warnPopup);

    warnPopup.querySelector('#btn-popup-close').addEventListener('click', () => {
        warnPopup.style.display = 'none';
    });
    warnPopup.querySelector('#btn-popup-activate').addEventListener('click', () => {
warnPopup.style.display = 'none';
        powerBtn.click(); // tetikle
    });

    // --- GLOBAL POWER TOGGLE ---
    const powerBtn = document.getElementById('global-power');
    const dashboard = document.querySelector('.dashboard-content');
    const sidebar = document.querySelector('.sidebar');

    // --- WHO AM I POPUP ---
    const whoAmIPopup = document.createElement('div');
    whoAmIPopup.id = 'whoami-popup-overlay';
    whoAmIPopup.className = 'popup-overlay';
    whoAmIPopup.style.display = 'none';
    whoAmIPopup.innerHTML = `
        <div class="whoami-popup">
            <div class="whoami-header">
                <h2 class="whoami-title"><i class="ti ti-info-circle"></i> Uygulama Amacı ve Yapılabilenler Özet Paneli</h2>
                <button id="btn-whoami-close-top" class="btn-primary" style="background: rgba(255,255,255,0.09); color: #fff; box-shadow: none;">Kapat</button>
            </div>
            <div class="whoami-grid">
                <div class="whoami-card">
                    <h4>Benim Amacım (Geliştirici Hedefi)</h4>
                    <p style="font-size: 0.88rem; line-height: 1.6;">Bu proje, akademik bitirme çalışmam kapsamında geliştirilmiş olup; siber güvenlik zafiyet analizlerini, ağ keşif mekanizmalarını ve defansif güvenlik kodlama pratiklerini bütünsel ve modern bir web arayüzünde uygulamalı olarak sunmayı, öğrencilerin ve araştırmacıların güvenlik bilincini pratik deneyimle artırmayı hedefler.</p>
                </div>
                <div class="whoami-card">
                    <h4>Uygulamanın Amacı</h4>
                    <p style="font-size: 0.88rem; line-height: 1.6;">Ağ taraması, OSINT tehdit istihbaratı, statik kod güvenliği (SAST) ve yapay zeka analiz desteğini tek bir platformda birleştiren hibrit bir güvenlik analiz merkezidir. Amaç, siber savunma süreçlerini pratikleştirip tek çatı altında görselleştirmektir.</p>
                </div>
                <div class="whoami-card">
                    <h4>Uygulamanın Yapabildikleri (Ağ ve OSINT)</h4>
                    <p style="line-height: 1.6; font-size: 0.82rem;">
                        • <strong>Ping / ICMP Keşfi:</strong> Eş zamanlı ping atar ve IPinfo OSINT motoruyla konum/ISP bilgisi çeker.<br>
                        • <strong>Port Taraması:</strong> Kritik kapıları 2 saniyenin altında analiz eder.<br>
                        • <strong>Derin Port (Banner):</strong> Çalışan servis versiyonunu tespit eder.<br>
                        • <strong>DoS Testi:</strong> Sunucu yük ve stres sınırlarını test eder.<br>
                        • <strong>Email Sızıntı & VirusTotal:</strong> Dark Web sızıntılarını ve 70+ antivirüs motorunun URL raporunu sorgular.
                    </p>
                </div>
                <div class="whoami-card">
                    <h4>Uygulamanın Yapabildikleri (Kod & Kripto)</h4>
                    <p style="line-height: 1.6; font-size: 0.82rem;">
                        • <strong>SAST Analizörü:</strong> Python kodlarındaki zafiyetleri analiz eder ve AI ile triyaj raporu sunar.<br>
                        • <strong>Oturum & Çerez Denetimi:</strong> Cookie güvenlik bayraklarını raporlar.<br>
                        • <strong>Şifre Güç Analizi:</strong> Entropi analizi ve sızıntı sorgusu yapar.<br>
                        • <strong>Kripto Modülleri:</strong> MAC OUI tespiti, MD5/SHA256 hash üretimi ve kırılması, AES/DES/RSA şifreleme simülasyonu sunar.
                    </p>
                </div>
            </div>
            <div class="whoami-footer">
                <button id="btn-whoami-close-bottom" class="btn-primary"><i class="ti ti-shield"></i> Anladım</button>
            </div>
        </div>
    `;
    document.body.appendChild(whoAmIPopup);

    function closeWhoAmI() {
        whoAmIPopup.style.display = 'none';
    }

    if (btnWhoAmI) {
        btnWhoAmI.addEventListener('click', () => {
            whoAmIPopup.style.display = 'flex';
        });
    }
    whoAmIPopup.addEventListener('click', (e) => {
        if (e.target === whoAmIPopup) closeWhoAmI();
    });
    whoAmIPopup.querySelector('#btn-whoami-close-top').addEventListener('click', closeWhoAmI);
    whoAmIPopup.querySelector('#btn-whoami-close-bottom').addEventListener('click', closeWhoAmI);

    // --- YAPILANLAR POPUP ---
    const btnYapilanlar = document.getElementById('btn-yapilanlar');
    const yapilanlarPopup = document.createElement('div');
    yapilanlarPopup.id = 'yapilanlar-popup-overlay';
    yapilanlarPopup.className = 'popup-overlay';
    yapilanlarPopup.style.display = 'none';
    yapilanlarPopup.innerHTML = `
        <div class="whoami-popup" style="border-color: rgba(168, 85, 247, 0.4); background: radial-gradient(circle at top right, rgba(168, 85, 247, 0.12), transparent 45%), linear-gradient(145deg, rgba(8, 10, 18, 0.96), rgba(10, 12, 20, 0.98)); box-shadow: 0 30px 80px rgba(0, 0, 0, 0.6), 0 0 40px rgba(168, 85, 247, 0.12); width: min(860px, 92vw);">
            <div class="whoami-header">
                <h2 class="whoami-title" style="color: #c084fc; font-size:1.25rem; display:flex; align-items:center; gap:0.5rem;"><i class="ti ti-checklist"></i> Projenin Sıfırdan Günümüze Gelişim Süreci</h2>
                <button id="btn-yapilanlar-close-top" class="btn-primary" style="background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); font-weight: 600; padding: 0.4rem 1rem; border-radius: 0.75rem; box-shadow: none;">Kapat</button>
            </div>
            <div style="max-height: 52vh; overflow-y: auto; padding-right: 8px; margin-bottom: 1.5rem; color: var(--text-secondary); line-height: 1.6; font-size: 0.9rem;">
                
                <!-- 0. Adım -->
                <div class="step-bubble-card">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem;">
                        <span style="background: rgba(168, 85, 247, 0.12); color: #c084fc; padding: 0.3rem 0.85rem; border-radius: 100vw; font-size: 0.78rem; font-weight: 700; display: inline-flex; align-items: center; gap: 0.35rem; border: 1px solid rgba(168, 85, 247, 0.25);">
                            <i class="ti ti-flag"></i> 0. Adım
                        </span>
                        <span style="color: rgba(168, 85, 247, 0.6); font-size: 0.8rem; font-weight: 600;">Her Şey Nasıl Başladı?</span>
                    </div>
                    <h4 style="color: #fff; font-size: 1.05rem; font-weight: 700; margin-bottom: 0.5rem;">Projenin İlk Hali (Sıfır Noktası)</h4>
                    <p style="color: var(--text-secondary); font-size: 0.88rem; line-height: 1.6; margin: 0;">Projeye ilk başladığımda elimde sadece Flask ile yazılmış, birkaç kutucuk ve butondan oluşan çok basit bir taslak vardı. Ne göze hitap eden bir tasarımı bulunuyordu ne de arkada çalışan bir ağ tarama veya tehdit istihbaratı özelliği... Tamamen boş bir sayfaydı diyebilirim.</p>
                </div>

                <!-- 1. Adım -->
                <div class="step-bubble-card">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem;">
                        <span style="background: rgba(168, 85, 247, 0.12); color: #c084fc; padding: 0.3rem 0.85rem; border-radius: 100vw; font-size: 0.78rem; font-weight: 700; display: inline-flex; align-items: center; gap: 0.35rem; border: 1px solid rgba(168, 85, 247, 0.25);">
                            <i class="ti ti-brush"></i> 1. Adım
                        </span>
                        <span style="color: rgba(168, 85, 247, 0.6); font-size: 0.8rem; font-weight: 600;">Göze Hitap Eden Modern Bir Görünüm</span>
                    </div>
                    <h4 style="color: #fff; font-size: 1.05rem; font-weight: 700; margin-bottom: 0.5rem;">Tasarım ve Arayüz Revizyonu</h4>
                    <p style="color: var(--text-secondary); font-size: 0.88rem; line-height: 1.6; margin: 0;">İlk iş olarak projenin arayüzünü günümüz siber güvenlik uygulamalarına yakışacak şekilde baştan tasarladım. Karanlık tema, arkada dönen yumuşak neon renkler ve modern cam paneller ekledim. Ayrıca sol tarafa rahatça gezinebileceğimiz dinamik menüler ve anlık durum kartları koydum.</p>
                </div>

                <!-- 2. Adım -->
                <div class="step-bubble-card">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem;">
                        <span style="background: rgba(168, 85, 247, 0.12); color: #c084fc; padding: 0.3rem 0.85rem; border-radius: 100vw; font-size: 0.78rem; font-weight: 700; display: inline-flex; align-items: center; gap: 0.35rem; border: 1px solid rgba(168, 85, 247, 0.25);">
                            <i class="ti ti-network"></i> 2. Adım
                        </span>
                        <span style="color: rgba(168, 85, 247, 0.6); font-size: 0.8rem; font-weight: 600;">Arka Plandaki Motorları Isındırıyoruz</span>
                    </div>
                    <h4 style="color: #fff; font-size: 1.05rem; font-weight: 700; margin-bottom: 0.6rem;">Asenkron Ağ Keşif & DoS Motorları</h4>
                    <p style="color: var(--text-secondary); font-size: 0.88rem; line-height: 1.6; margin: 0;">
                        Arayüzü toparladıktan sonra işin asıl teknik kısmına geçtim ve arka planda çalışan güçlü araçlar geliştirdim:<br>
                        • <strong>Ping / ICMP:</strong> IP adreslerinin çalışıp çalışmadığını kontrol eden ping özelliğini ekledim.<br>
                        • <strong>Hızlı Port Tarama:</strong> Çok hızlı çalışan ve açık kapıları (portları) anında bulabilen çoklu iş parçacıklı (multithreaded) bir tarayıcı yazdım.<br>
                        • <strong>Derin Port Analizi (Banner):</strong> Portlarda hangi yazılımların ve versiyonların çalıştığını tespit eden bir sistem ekledim.<br>
                        • <strong>DoS Testi:</strong> Sunucuların yoğun HTTP trafiği altında nasıl tepki verdiğini ve dayanıklılık limitlerini ölçen bir yük test aracı geliştirdim.
                    </p>
                </div>

                <!-- 3. Adım -->
                <div class="step-bubble-card">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem;">
                        <span style="background: rgba(168, 85, 247, 0.12); color: #c084fc; padding: 0.3rem 0.85rem; border-radius: 100vw; font-size: 0.78rem; font-weight: 700; display: inline-flex; align-items: center; gap: 0.35rem; border: 1px solid rgba(168, 85, 247, 0.25);">
                            <i class="ti ti-search"></i> 3. Adım
                        </span>
                        <span style="color: rgba(168, 85, 247, 0.6); font-size: 0.8rem; font-weight: 600;">Dış Dünya ile Entegrasyon</span>
                    </div>
                    <h4 style="color: #fff; font-size: 1.05rem; font-weight: 700; margin-bottom: 0.6rem;">Canlı OSINT & Tehdit İstihbaratı</h4>
                    <p style="color: var(--text-secondary); font-size: 0.88rem; line-height: 1.6; margin: 0;">
                        Sadece yerel taramalarla sınırlı kalmak istemedim, bu yüzden canlı siber istihbarat kaynaklarını projeme entegre ettim:<br>
                        • <strong>IPinfo Harita ve ISP Desteği:</strong> Ping attığımız hedefin nerede olduğunu, hangi internet sağlayıcısını kullandığını haritada göstermeye başladık (ve bunu arkada 24 saat önbelleğe alarak hızlandırdım).<br>
                        • <strong>Sızıntı Kontrolü:</strong> E-posta adreslerinin internete sızıp sızmadığını sorgulayan Dark Web tarayıcısını ekledim.<br>
                        • <strong>Güvenli Link Analizi:</strong> Şüpheli linkleri 70'ten fazla antivirüs motoruna tek tıkla taratan VirusTotal API entegrasyonunu tamamladım.
                    </p>
                </div>

                <!-- 4. Adım -->
                <div class="step-bubble-card">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem;">
                        <span style="background: rgba(168, 85, 247, 0.12); color: #c084fc; padding: 0.3rem 0.85rem; border-radius: 100vw; font-size: 0.78rem; font-weight: 700; display: inline-flex; align-items: center; gap: 0.35rem; border: 1px solid rgba(168, 85, 247, 0.25);">
                            <i class="ti ti-code"></i> 4. Adım
                        </span>
                        <span style="color: rgba(168, 85, 247, 0.6); font-size: 0.8rem; font-weight: 600;">Güvenlik Analizlerini Derinleştiriyoruz</span>
                    </div>
                    <h4 style="color: #fff; font-size: 1.05rem; font-weight: 700; margin-bottom: 0.6rem;">Kod, Oturum ve Kriptografi Güvenliği</h4>
                    <p style="color: var(--text-secondary); font-size: 0.88rem; line-height: 1.6; margin: 0;">
                        İstasyonu daha da zenginleştirmek için yeni analiz ve şifreleme modülleri geliştirdim:<br>
                        • <strong>Kod Analizi (SAST):</strong> Python kodlarındaki açıkları bulup yapay zekayla çözen bir kod tarayıcısı hazırladım.<br>
                        • <strong>Çerez Analizi:</strong> Sitelerdeki çerez güvenlik bayraklarını (Secure, HttpOnly vb.) inceleyen bir analizör ekledim.<br>
                        • <strong>Şifre Güç Ölçer:</strong> Şifrelerin ne kadar sürede kırılabileceğini hesaplayan ve internette ifşa olup olmadığını kontrol eden bir sistem kurdum.<br>
                        • <strong>Kriptografi Laboratuvarı:</strong> Donanım üreticilerini bulma, MD5/SHA256 hash işlemleri ve AES/DES/RSA şifreleme simülatörlerini projeye ekledim.
                    </p>
                </div>

                <!-- 5. Adım -->
                <div class="step-bubble-card" style="margin-bottom: 0;">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem;">
                        <span style="background: rgba(168, 85, 247, 0.12); color: #c084fc; padding: 0.3rem 0.85rem; border-radius: 100vw; font-size: 0.78rem; font-weight: 700; display: inline-flex; align-items: center; gap: 0.35rem; border: 1px solid rgba(168, 85, 247, 0.25);">
                            <i class="ti ti-lock"></i> 5. Adım
                        </span>
                        <span style="color: rgba(168, 85, 247, 0.6); font-size: 0.8rem; font-weight: 600;">Son Dokunuşlar ve Koruma</span>
                    </div>
                    <h4 style="color: #fff; font-size: 1.05rem; font-weight: 700; margin-bottom: 0.5rem;">Kılavuz, Taahhütname & Güvenlik Sıkılaştırması</h4>
                    <p style="color: var(--text-secondary); font-size: 0.88rem; line-height: 1.6; margin: 0;">Proje bitmeye yakınken kullanıcı dostu olmasını istedim. İlk defa girenler için tüm sekmelere özel rehber popupları ve yardım tooltip (?) sistemleri yerleştirdim. Ayrıca API anahtarlarımızın güvenliği için ".env" yapısına geçtim ve tarayıcı önbellek (cache) sıkıntılarını çözmek için dinamik sürüm kontrolü uygulayarak projeyi tamamladım.</p>
                </div>

            </div>
            <div class="whoami-footer" style="border-top: 1px solid rgba(255,255,255,0.05); padding-top: 1rem;">
                <button id="btn-yapilanlar-close-bottom" class="btn-primary" style="background: linear-gradient(135deg, #a855f7, #6b21a8); box-shadow: 0 0 15px rgba(168, 85, 247, 0.35);"><i class="ti ti-check"></i> Raporu İnceledim</button>
            </div>
        </div>
    `;
    document.body.appendChild(yapilanlarPopup);

    function closeYapilanlar() {
        yapilanlarPopup.style.display = 'none';
    }

    if (btnYapilanlar) {
        btnYapilanlar.addEventListener('click', () => {
            yapilanlarPopup.style.display = 'flex';
        });
    }
    yapilanlarPopup.addEventListener('click', (e) => {
        if (e.target === yapilanlarPopup) closeYapilanlar();
    });
    yapilanlarPopup.querySelector('#btn-yapilanlar-close-top').addEventListener('click', closeYapilanlar);
    yapilanlarPopup.querySelector('#btn-yapilanlar-close-bottom').addEventListener('click', closeYapilanlar);

    // --- DEVELOPER POPUP ---
    const btnDeveloper = document.getElementById('btn-developer');
    const developerPopup = document.createElement('div');
    developerPopup.id = 'developer-popup-overlay';
    developerPopup.className = 'popup-overlay';
    developerPopup.style.display = 'none';
    developerPopup.innerHTML = `
        <div class="whoami-popup" style="max-width: 480px; border-color: rgba(16, 185, 129, 0.4); background: radial-gradient(circle at top right, rgba(16, 185, 129, 0.12), transparent 45%), linear-gradient(145deg, rgba(8, 10, 18, 0.96), rgba(10, 12, 20, 0.98)); box-shadow: 0 30px 80px rgba(0, 0, 0, 0.6), 0 0 40px rgba(16, 185, 129, 0.12); animation: aerodynamicFadeIn 0.3s ease-out;">
            <div class="whoami-header">
                <h2 class="whoami-title" style="color: #34d399; font-size:1.25rem; display:flex; align-items:center; gap:0.5rem;"><i class="ti ti-user-code"></i> Geliştirici Bilgileri</h2>
                <button id="btn-developer-close-top" class="btn-primary" style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); font-weight: 600; padding: 0.4rem 1rem; border-radius: 0.75rem; box-shadow: none;">Kapat</button>
            </div>
            <div style="background: rgba(16, 185, 129, 0.03); border: 1px solid rgba(16, 185, 129, 0.15); border-radius: 1.25rem; padding: 2rem; text-align: center; margin-bottom: 1rem;">
                <div style="width: 80px; height: 80px; border-radius: 50%; background: rgba(16, 185, 129, 0.12); border: 2px solid rgba(16, 185, 129, 0.35); display: flex; align-items: center; justify-content: center; margin: 0 auto 1.25rem auto;">
                    <i class="ti ti-user-code" style="font-size: 2.5rem; color: #34d399;"></i>
                </div>
                <h3 style="color: #fff; font-size: 1.3rem; font-weight: 800; margin-bottom: 0.5rem;">Ali İhsan GÜLŞEN</h3>
                <p style="color: #34d399; font-size: 0.9rem; font-weight: 600; margin-bottom: 1.5rem; letter-spacing: 0.05em; text-transform: uppercase;">Cyber Sentinel Geliştiricisi</p>
                
                <div style="display: flex; flex-direction: column; gap: 0.85rem; text-align: left; background: rgba(0, 0, 0, 0.2); padding: 1.25rem; border-radius: 1rem; border: 1px solid rgba(255,255,255,0.03);">
                    <div style="display: flex; align-items: center; gap: 0.75rem;">
                        <i class="ti ti-id-badge" style="color: #34d399; font-size: 1.2rem;"></i>
                        <span style="color: var(--text-secondary); font-size: 0.9rem;"><strong>Okul No:</strong> 2205314014</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.75rem;">
                        <i class="ti ti-mail" style="color: #34d399; font-size: 1.2rem;"></i>
                        <span style="color: var(--text-secondary); font-size: 0.9rem;"><strong>E-Posta:</strong> <a href="mailto:aligulsen.0619@gmail.com" style="color: var(--accent-cyan); text-decoration: none;">aligulsen.0619@gmail.com</a></span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.75rem;">
                        <i class="ti ti-brand-github" style="color: #34d399; font-size: 1.2rem;"></i>
                        <span style="color: var(--text-secondary); font-size: 0.9rem;"><strong>GitHub:</strong> <a href="https://github.com/grayrookie" target="_blank" style="color: var(--accent-magenta); text-decoration: none; font-weight: 600;">github.com/grayrookie</a></span>
                    </div>
                </div>
            </div>
            <div class="whoami-footer" style="border-top: 1px solid rgba(255,255,255,0.05); padding-top: 1rem;">
                <button id="btn-developer-close-bottom" class="btn-primary" style="background: linear-gradient(135deg, #10b981, #047857); box-shadow: 0 0 15px rgba(16, 185, 129, 0.35); width: 100%; justify-content: center;"><i class="ti ti-check"></i> Profili İnceledim</button>
            </div>
        </div>
    `;
    document.body.appendChild(developerPopup);

    function closeDeveloper() {
        developerPopup.style.display = 'none';
    }

    if (btnDeveloper) {
        btnDeveloper.addEventListener('click', () => {
            developerPopup.style.display = 'flex';
        });
    }
    developerPopup.addEventListener('click', (e) => {
        if (e.target === developerPopup) closeDeveloper();
    });
    developerPopup.querySelector('#btn-developer-close-top').addEventListener('click', closeDeveloper);
    developerPopup.querySelector('#btn-developer-close-bottom').addEventListener('click', closeDeveloper);


    
    // Create boot overlay
    const overlay = document.createElement('div');
    overlay.className = 'boot-overlay';
    overlay.style.display = 'none';
    overlay.innerHTML = `
        <div class="loader" style="width: 80px; height: 80px; border-width: 6px; border-top-color: var(--accent-cyan);"></div>
        <h2>SİSTEM BAŞLATILIYOR</h2>
        <p>Lütfen Bekleyiniz Araçlar Aktifleştiriliyor...</p>
        <div class="boot-timer-text">00:<span id="boot-timer">10</span></div>
    `;
    dashboard.appendChild(overlay);

    let isStationActive = true;
    let isBooting = false;

    function deactivateStation() {
        if (!isStationActive) return;
        isStationActive = false;
        powerBtn.className = 'status-badge offline';
        powerBtn.innerHTML = '<i class="ti ti-power"></i> İSTASYON DEVRE DIŞI';
        
        // Sadece menü tuşlarını ve içerikleri grileştir, sol üst amblemi hariç tut
        document.querySelector('.nav-menu').classList.add('app-disabled');
        
        // Amblemi Uyku Modu (Buz Mavisi) rengine sok
        const emblem = document.getElementById('sidebar-dragon-emblem');
        if (emblem) {
            emblem.dataset.onlineColor = emblem.style.color || 'var(--accent-cyan)';
            emblem.dataset.onlineFilter = emblem.style.filter || '';
            emblem.style.color = '#3b82f6'; // Buz mavisi
            emblem.style.filter = 'drop-shadow(0 0 15px rgba(59, 130, 246, 0.6))'; // Hafif parlama
        }
        
        // Disable all tabs inside dashboard except overlay
        Array.from(dashboard.children).forEach(c => {
            if (c !== overlay) c.classList.add('app-disabled');
        });
    }

    function activateStation() {
        if (isStationActive) return;
        isStationActive = true;
        
        powerBtn.className = 'status-badge';
        powerBtn.innerHTML = '<span class="pulse"></span> İSTASYON AKTİF';
        
        document.querySelector('.nav-menu').classList.remove('app-disabled');
        
        // Amblemi orijinal aktif neon rengine geri çevir
        const emblem = document.getElementById('sidebar-dragon-emblem');
        if (emblem && emblem.dataset.onlineColor) {
            emblem.style.color = emblem.dataset.onlineColor;
            emblem.style.filter = emblem.dataset.onlineFilter;
        }
        
        Array.from(dashboard.children).forEach(c => c.classList.remove('app-disabled'));
    }

    powerBtn.addEventListener('click', () => {
        if (isBooting) return; // Prevent clicking during boot

        if (isStationActive) {
            deactivateStation();
        } else {
            // Boot Up System
            isBooting = true;
            powerBtn.className = 'status-badge booting';
            powerBtn.innerHTML = '<span class="loader" style="width:12px;height:12px;border-width:2px;margin-right:8px;animation-duration:0.5s"></span> BAŞLATILIYOR';
            
            overlay.style.display = 'flex';
            let timeLeft = 10;
            const timerSpan = overlay.querySelector('#boot-timer');
            timerSpan.textContent = timeLeft;

            const bootInterval = setInterval(() => {
                timeLeft--;
                timerSpan.textContent = timeLeft < 10 ? '0' + timeLeft : timeLeft;
                
                if (timeLeft <= 0) {
                    clearInterval(bootInterval);
                    isBooting = false;
                    activateStation();
                    overlay.style.display = 'none';
                }
            }, 1000);
        }
    });

    // --- KILL SWITCH (ACİL DURUM İZOLASYON) MANTIĞI ---
    const btnKillSwitch = document.getElementById('btn-kill-switch');

    function updateKillSwitchUi(isIsolated) {
        if (!btnKillSwitch) return;
        if (isIsolated) {
            btnKillSwitch.style.background = '#ff3333';
            btnKillSwitch.style.borderColor = '#cc2222';
            btnKillSwitch.style.boxShadow = '0 0 20px rgba(255, 51, 51, 0.6)';
            btnKillSwitch.innerHTML = '<i class="ti ti-alert-triangle"></i><span>💥 SİSTEM İZOLE EDİLDİ</span>';
        } else {
            btnKillSwitch.style.background = '#990000';
            btnKillSwitch.style.borderColor = '#7f0000';
            btnKillSwitch.style.boxShadow = '0 0 15px rgba(153, 0, 0, 0.4)';
            btnKillSwitch.innerHTML = '<i class="ti ti-alert-triangle"></i><span>🚨 ACİL DURUM BUTONU</span>';
        }
    }

    function showEmergencyPopup(isIsolated) {
        // Remove existing emergency popup if any
        const existing = document.getElementById('emergency-popup-overlay');
        if (existing) existing.remove();
        
        const overlay = document.createElement('div');
        overlay.id = 'emergency-popup-overlay';
        overlay.className = 'popup-overlay';
        overlay.style.zIndex = '70000';
        overlay.style.display = 'flex';
        
        if (isIsolated) {
            // First show "connecting/isolating" loading state
            overlay.innerHTML = `
                <div style="background: rgba(15, 15, 20, 0.96); padding: 3rem; border-radius: 1.5rem; text-align: center; border: 1px solid #ff3333; box-shadow: 0 0 40px rgba(255, 51, 51, 0.2); max-width: 480px; width: 90%; animation: aerodynamicFadeIn 0.3s ease-out;">
                    <span class="loader" style="width: 60px; height: 60px; border-width: 4px; border-top-color: #ff3333; display: inline-block; margin-bottom: 1.5rem;"></span>
                    <h2 style="color: #fff; margin-bottom: 1rem; font-size: 1.4rem; letter-spacing: 0.05em; font-weight: 800; text-transform: uppercase;">AĞ İZOLE EDİLİYOR</h2>
                    <p style="color: var(--text-secondary); line-height: 1.6; font-size: 0.95rem;">[🔄] Yerel Ağ Arabirimleri (NIC Interface) pasif ediliyor, lütfen bekleyiniz...</p>
                </div>
            `;
            document.body.appendChild(overlay);
            
            setTimeout(() => {
                // Update to final success state
                overlay.innerHTML = `
                    <div style="background: rgba(15, 15, 20, 0.96); padding: 3rem; border-radius: 1.5rem; text-align: center; border: 1px solid #ff3333; box-shadow: 0 0 40px rgba(255, 51, 51, 0.35); max-width: 480px; width: 90%; animation: aerodynamicFadeIn 0.3s ease-out;">
                        <i class="ti ti-shield-lock" style="font-size: 3.8rem; color: #ff3333; margin-bottom: 1.5rem; filter: drop-shadow(0 0 10px #ff3333);"></i>
                        <h2 style="color: #fff; margin-bottom: 1rem; font-size: 1.5rem; letter-spacing: 0.05em; font-weight: 800; text-transform: uppercase;">🚨 SİBER KARANTİNA AKTİF</h2>
                        <p style="color: var(--text-secondary); line-height: 1.6; font-size: 0.95rem; margin-bottom: 2rem;">Tüm soket bağları koparıldı. Sunucu güvenli siber karantinaya alındı.</p>
                        <button id="btn-emergency-popup-close" class="btn-primary" style="background: #ff3333; color: #fff; font-weight: bold; width: 100%; justify-content: center; box-shadow: 0 0 15px rgba(255, 51, 51, 0.3);">Kapat</button>
                    </div>
                `;
                
                overlay.querySelector('#btn-emergency-popup-close').addEventListener('click', () => {
                    overlay.style.animation = 'aerodynamicFadeOut 0.3s forwards';
                    setTimeout(() => overlay.remove(), 300);
                });
                
                // Disable the station after quarantine success
                deactivateStation();
            }, 1200);
        } else {
            // Immediately show safe mode popup
            overlay.innerHTML = `
                <div style="background: rgba(15, 15, 20, 0.96); padding: 3rem; border-radius: 1.5rem; text-align: center; border: 1px solid var(--accent-green); box-shadow: 0 0 40px rgba(16, 185, 129, 0.35); max-width: 480px; width: 90%; animation: aerodynamicFadeIn 0.3s ease-out;">
                    <i class="ti ti-shield-check" style="font-size: 3.8rem; color: var(--accent-green); margin-bottom: 1.5rem; filter: drop-shadow(0 0 10px var(--accent-green));"></i>
                    <h2 style="color: #fff; margin-bottom: 1rem; font-size: 1.5rem; letter-spacing: 0.05em; font-weight: 800; text-transform: uppercase;">🟢 GÜVENLİ ÇEVRİMİÇİ MOD</h2>
                    <p style="color: var(--text-secondary); line-height: 1.6; font-size: 0.95rem; margin-bottom: 2rem;">Tehdit unsurları bertaraf edildi. Ağ arabirimleri yeniden ayağa kaldırıldı. Sistem çevrimiçi.</p>
                    <button id="btn-emergency-popup-close" class="btn-primary" style="background: var(--accent-green); color: #000; font-weight: bold; width: 100%; justify-content: center; box-shadow: 0 0 15px rgba(16, 185, 129, 0.3);">Kapat</button>
                </div>
            `;
            document.body.appendChild(overlay);
            
            overlay.querySelector('#btn-emergency-popup-close').addEventListener('click', () => {
                overlay.style.animation = 'aerodynamicFadeOut 0.3s forwards';
                setTimeout(() => overlay.remove(), 300);
            });
            
            // Re-activate the station immediately
            activateStation();
        }
    }

    if (btnKillSwitch) {
        btnKillSwitch.addEventListener('click', async () => {
            const isIsolatedNow = btnKillSwitch.innerHTML.includes('SİSTEM İZOLE EDİLDİ');
            if (typeof isStationActive !== 'undefined' && !isStationActive && !isIsolatedNow) {
                const warnPopup = document.getElementById('warn-popup');
                if (warnPopup) warnPopup.style.display = 'flex';
                return;
            }
            try {
                const response = await fetch('/api/security/kill-switch', { method: 'POST' });
                const data = await response.json();
                const isIsolated = data.is_network_isolated;
                updateKillSwitchUi(isIsolated);
                showEmergencyPopup(isIsolated);
            } catch (err) {
                console.error("Kill switch toggle error:", err);
            }
        });
        
        // Initial status check on load
        async function checkKillSwitchStatus() {
            try {
                const response = await fetch('/api/security/kill-switch/status');
                const data = await response.json();
                updateKillSwitchUi(data.is_network_isolated);
                if (data.is_network_isolated) {
                    deactivateStation();
                }
            } catch (err) {
                console.error("Kill switch status check error:", err);
            }
        }
        checkKillSwitchStatus();
    }

    // --- AI CHAT WIDGET & TRIAGE MANTIĞI ---
    const btnAiBubble = document.getElementById('btn-ai-bubble');
    const aiChatWindow = document.getElementById('ai-chat-window');
    const btnChatClose = document.getElementById('btn-chat-close');
    const chatMessages = document.getElementById('chat-messages');
    const chatInput = document.getElementById('chat-input');
    const btnChatSend = document.getElementById('btn-chat-send');

    // 1. Toggle Chat Window Popup
    if (btnAiBubble && aiChatWindow) {
        btnAiBubble.addEventListener('click', () => {
            const isClosed = aiChatWindow.style.display === 'none' || aiChatWindow.style.display === '';
            aiChatWindow.style.display = isClosed ? 'flex' : 'none';
        });
    }

    if (btnChatClose && aiChatWindow) {
        btnChatClose.addEventListener('click', () => {
            aiChatWindow.style.display = 'none';
        });
    }

    function appendChatMessage(sender, text, type = 'user') {
        const msgDiv = document.createElement('div');
        msgDiv.className = `chat-message ${type}`;
        
        let style = 'padding: 0.85rem; border-radius: 0.75rem; line-height: 1.5; font-size: 0.85rem; max-width: 85%;';
        let alignment = '';
        let icon = '';
        let title = '';
        
        if (type === 'user') {
            style += ' background: rgba(168, 85, 247, 0.1); border-right: 3px solid #a855f7; align-self: flex-end; color: #fff;';
            alignment = 'margin-left: auto;';
            icon = 'ti-user';
            title = 'Siz';
        } else if (type === 'system') {
            style += ' background: rgba(0, 240, 255, 0.05); border-left: 3px solid var(--accent-cyan); align-self: flex-start; color: var(--text-primary);';
            icon = 'ti-sparkles';
            title = 'Cyber Sentinel AI';
        }
        
        msgDiv.style.cssText = style + alignment;
        
        msgDiv.innerHTML = `
            <div style="font-weight: 700; margin-bottom: 0.25rem; color: ${type === 'user' ? '#c084fc' : 'var(--accent-cyan)'}; font-size: 0.75rem;">
                <i class="ti ${icon}"></i> ${title}
            </div>
            <div style="white-space: pre-wrap; font-family: inherit;">${text}</div>
        `;
        
        chatMessages.appendChild(msgDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    async function sendChatMessage() {
        const text = chatInput.value.trim();
        if (!text) return;
        
        chatInput.value = '';
        appendChatMessage('Siz', text, 'user');
        
        // Show loading indicator
        const loadingDiv = document.createElement('div');
        loadingDiv.id = 'chat-loading-indicator';
        loadingDiv.className = 'chat-message system';
        loadingDiv.style.cssText = 'background: rgba(0, 240, 255, 0.02); border-left: 3px dashed var(--accent-cyan); align-self: flex-start; padding: 0.85rem; border-radius: 0.75rem; color: var(--text-secondary); font-size: 0.82rem;';
        loadingDiv.innerHTML = '<span class="loader" style="width:12px;height:12px;border-width:2px;display:inline-block;margin-right:8px;"></span> Düşünüyor...';
        chatMessages.appendChild(loadingDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
        
        try {
            const req = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text })
            });
            const data = await req.json();
            
            // Remove loading
            const loaderEl = document.getElementById('chat-loading-indicator');
            if (loaderEl) loaderEl.remove();
            
            if (data.error) {
                appendChatMessage('System', `Hata: ${data.error}`, 'system');
            } else {
                appendChatMessage('System', data.response, 'system');
            }
        } catch (err) {
            const loaderEl = document.getElementById('chat-loading-indicator');
            if (loaderEl) loaderEl.remove();
            appendChatMessage('System', `Bağlantı Hatası: Sunucu ile iletişim kurulamadı.`, 'system');
        }
    }

    if (btnChatSend) {
        btnChatSend.addEventListener('click', sendChatMessage);
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                sendChatMessage();
            }
        });
    }

    // Quick prompt buttons inside widget
    document.querySelectorAll('.btn-quick-prompt').forEach(btn => {
        btn.addEventListener('click', () => {
            const prompt = btn.dataset.prompt;
            chatInput.value = prompt;
            sendChatMessage();
        });
    });

    // "Yapay Zeka ile Analiz Et" buttons handler
    document.querySelectorAll('.btn-ai-analyze').forEach(btn => {
        btn.addEventListener('click', () => {
            const sourceId = btn.dataset.source;
            const sourceEl = document.getElementById(sourceId);
            if (!sourceEl) return;
            
            const textContent = sourceEl.innerText.trim();
            if (!textContent) return;
            
            const prompt = `Lütfen şu tarama/keşif bulgularını analiz et ve siber güvenlik risklerini Türkçe olarak açıkla:\n\n${textContent}`;
            
            // Auto open widget chat window if closed
            if (aiChatWindow) {
                aiChatWindow.style.display = 'flex';
            }
            
            chatInput.value = prompt;
            sendChatMessage();
        });
    });

    // AI Triage Button Handler (SAST deep triage)
    const btnAiTriage = document.getElementById('btn-ai-triage');
    const aiTriageResults = document.getElementById('ai-triage-results');
    
    if (btnAiTriage) {
        btnAiTriage.addEventListener('click', async () => {
            const codeVal = document.getElementById('sast-code').value;
            if (!codeVal.trim()) return;
            
            aiTriageResults.innerHTML = '';
            aiTriageResults.style.display = 'block';
            aiTriageResults.classList.remove('empty');
            
            const originalText = btnAiTriage.innerHTML;
            btnAiTriage.innerHTML = '<span class="loader" style="width:15px;height:15px;border-width:2px;"></span> AI TRİYAJ YAPILIYOR...';
            btnAiTriage.disabled = true;
            
            try {
                const req = await fetch('/api/ai/triage', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: codeVal })
                });
                const data = await req.json();
                
                if (data.error) {
                    throw new Error(data.error);
                }
                
                // Draw a beautiful triage report
                let triageHtml = `
                    <div style="padding: 1.5rem; border-radius: 1.5rem; background: rgba(0, 0, 0, 0.4); border: 1px solid var(--accent-magenta); margin-top: 1rem;">
                        <h4 style="color: var(--accent-magenta); font-size: 1.1rem; font-weight: 800; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.75rem; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;"><i class="ti ti-wand"></i> YAPAY ZEKA ZAFİYET TRİYAJ RAPORU</h4>
                        
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
                            <div class="glass-panel" style="padding: 1rem; border-radius: 0.75rem; border-color: rgba(255,255,255,0.02); text-align: center;">
                                <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase;">Zafiyet Skoru</div>
                                <div style="font-size: 2.2rem; font-weight: 900; color: ${data.score >= 70 ? 'var(--accent-red)' : data.score >= 40 ? '#eab308' : 'var(--accent-green)'}; text-shadow: 0 0 10px rgba(255,0,0,0.2);">${data.score} / 100</div>
                            </div>
                            <div class="glass-panel" style="padding: 1rem; border-radius: 0.75rem; border-color: rgba(255,255,255,0.02); text-align: center;">
                                <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase;">Saldırı Yüzeyi</div>
                                <div style="font-size: 1.1rem; font-weight: 800; color: #fff; margin-top: 0.5rem;">${data.attack_surface || 'Bilinmiyor'}</div>
                            </div>
                            <div class="glass-panel" style="padding: 1rem; border-radius: 0.75rem; border-color: rgba(255,255,255,0.02); text-align: center;">
                                <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase;">Sahte Pozitif mi?</div>
                                <div style="font-size: 1.1rem; font-weight: 800; color: ${data.false_positive ? 'var(--accent-green)' : 'var(--accent-red)'}; margin-top: 0.5rem;">${data.false_positive ? 'EVET (Yalancı İhbar)' : 'HAYIR (Gerçek Tehdit)'}</div>
                            </div>
                        </div>

                        <div style="margin-bottom: 1.5rem;">
                            <h5 style="color: var(--accent-cyan); font-size: 0.9rem; font-weight: 700; margin-bottom: 0.5rem;"><i class="ti ti-network"></i> Zafiyet Analiz Detayları</h5>
                            <p style="color: var(--text-secondary); line-height: 1.5; font-size: 0.88rem; text-align: justify; white-space: pre-line;">${data.analysis}</p>
                        </div>
                        
                        <div>
                            <h5 style="color: var(--accent-green); font-size: 0.9rem; font-weight: 700; margin-bottom: 0.5rem;"><i class="ti ti-code"></i> Güvenli Kod Önerisi (Remediation)</h5>
                            <pre style="background: rgba(0,0,0,0.6); padding: 1rem; border-radius: 0.5rem; border: 1px solid rgba(255,255,255,0.05); color: #a3e635; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; overflow-x: auto; white-space: pre-wrap;"><code>${data.secure_code}</code></pre>
                        </div>
                    </div>
                `;
                
                aiTriageResults.innerHTML = triageHtml;
                
            } catch (err) {
                const errorLine = document.createElement('div');
                errorLine.className = 'log-line';
                errorLine.innerHTML = `<i class="ti ti-circle-x status-down"></i> <span style="color:var(--accent-red)">[Hata]: ${err.message}</span>`;
                aiTriageResults.appendChild(errorLine);
            } finally {
                btnAiTriage.innerHTML = originalText;
                btnAiTriage.disabled = false;
            }
        });
    }

    // ─────────────────────────────────────────────────────────────
    // KRİPTOGRAFİ LABORATUVARI
    // ─────────────────────────────────────────────────────────────
    let cipherMode = 'encrypt'; // global mod

    // Algoritma değişince anahtar label ve RSA panelini güncelle
    window.cipherAlgoChanged = function() {
        const algo = document.getElementById('cipher-algo').value;
        const label = document.getElementById('cipher-key-label');
        const keyInput = document.getElementById('cipher-key');
        const rsaPanel = document.getElementById('rsa-keygen-panel');
        const keyWrapper = document.getElementById('cipher-key-wrapper');

        const labels = {
            caesar:  '🔢 Kaydırma Miktarı (Sayı, örn: 3)',
            vigenere:'🔑 Anahtar Kelime (örn: SIBER)',
            des:     '🔑 DES Anahtarı (8 karakter)',
            aes:     '🔑 AES Parolası (Passphrase)',
            rsa:     '🔐 RSA Anahtarı (PEM formatında Public/Private Key)'
        };
        const placeholders = {
            caesar:  'Örn: 3',
            vigenere:'Örn: SIBER',
            des:     'Örn: 12345678',
            aes:     'Güçlü bir parola girin...',
            rsa:     '-----BEGIN PUBLIC KEY----- veya -----BEGIN RSA PRIVATE KEY-----'
        };

        label.innerHTML = `<i class="ti ti-key"></i> ${labels[algo] || 'Anahtar'}`;
        keyInput.placeholder = placeholders[algo] || '';
        rsaPanel.style.display = (algo === 'rsa') ? 'block' : 'none';
        keyWrapper.style.display = (algo === 'rsa') ? 'none' : 'block';
    };

    // Şifrele / Çöz modu toggle
    window.setCipherMode = function(mode) {
        cipherMode = mode;
        const encBtn = document.getElementById('cipher-mode-enc');
        const decBtn = document.getElementById('cipher-mode-dec');
        const label  = document.getElementById('btn-cipher-label');

        if (mode === 'encrypt') {
            encBtn.style.background = 'linear-gradient(135deg,var(--accent-blue),#7c3aed)';
            encBtn.style.color = '#fff';
            encBtn.style.boxShadow = '';
            decBtn.style.background = 'rgba(255,255,255,0.05)';
            decBtn.style.color = 'var(--text-secondary)';
            decBtn.style.boxShadow = 'none';
            label.textContent = 'Şifrele';
        } else {
            decBtn.style.background = 'linear-gradient(135deg,var(--accent-green),#059669)';
            decBtn.style.color = '#000';
            decBtn.style.boxShadow = '';
            encBtn.style.background = 'rgba(255,255,255,0.05)';
            encBtn.style.color = 'var(--text-secondary)';
            encBtn.style.boxShadow = 'none';
            label.textContent = 'Şifreyi Çöz';
        }
    };

    // Şifreleme / Çözme çalıştır
    const btnCipherRun = document.getElementById('btn-cipher-run');
    if (btnCipherRun) {
        btnCipherRun.addEventListener('click', async () => {
            const algo  = document.getElementById('cipher-algo').value;
            const text  = document.getElementById('cipher-input').value.trim();
            const key   = algo === 'rsa'
                ? (cipherMode === 'encrypt'
                    ? document.getElementById('rsa-public-key').value.trim()  || document.getElementById('cipher-key').value.trim()
                    : document.getElementById('rsa-private-key').value.trim() || document.getElementById('cipher-key').value.trim())
                : document.getElementById('cipher-key').value.trim();

            if (!text) {
                alert('Lütfen şifrelenecek/çözülecek metni girin.');
                return;
            }

            const originalHtml = btnCipherRun.innerHTML;
            btnCipherRun.innerHTML = '<span class="loader" style="width:15px;height:15px;border-width:2px;"></span> İşleniyor...';
            btnCipherRun.disabled = true;

            try {
                const req = await fetch('/api/crypto/cipher', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ algorithm: algo, mode: cipherMode, text, key })
                });
                const data = await req.json();

                if (data.error) {
                    document.getElementById('cipher-output-wrapper').style.display = 'block';
                    document.getElementById('cipher-output').value = `[HATA]: ${data.error}`;
                    document.getElementById('cipher-output').style.color = 'var(--accent-red)';
                    document.getElementById('cipher-analysis').textContent = '';
                } else {
                    document.getElementById('cipher-output-wrapper').style.display = 'block';
                    document.getElementById('cipher-output').value = data.result;
                    document.getElementById('cipher-output').style.color = '#a3e635';
                    document.getElementById('cipher-analysis').textContent = data.analysis || '';

                    // Analiz kutusunu algoritmaya göre renklendir
                    const analysisEl = document.getElementById('cipher-analysis');
                    if (algo === 'aes' || algo === 'rsa') {
                        analysisEl.style.borderColor = 'rgba(0,240,255,0.15)';
                        analysisEl.style.color = 'var(--accent-cyan)';
                    } else if (algo === 'des' || algo === 'caesar' || algo === 'vigenere') {
                        analysisEl.style.borderColor = 'rgba(234,179,8,0.2)';
                        analysisEl.style.color = '#eab308';
                    }
                }
            } catch (err) {
                document.getElementById('cipher-output-wrapper').style.display = 'block';
                document.getElementById('cipher-output').value = `[BAĞLANTI HATASI]: ${err.message}`;
            } finally {
                btnCipherRun.innerHTML = originalHtml;
                btnCipherRun.disabled = false;
            }
        });
    }

    // RSA Anahtar Çifti Üret
    const btnRsaKeygen = document.getElementById('btn-rsa-keygen');
    if (btnRsaKeygen) {
        btnRsaKeygen.addEventListener('click', async () => {
            const bits = parseInt(document.getElementById('rsa-bits').value) || 2048;
            const originalHtml = btnRsaKeygen.innerHTML;
            btnRsaKeygen.innerHTML = '<span class="loader" style="width:13px;height:13px;border-width:2px;"></span> Üretiliyor...';
            btnRsaKeygen.disabled = true;

            try {
                const req = await fetch('/api/crypto/rsa-keygen', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ bits })
                });
                const data = await req.json();
                if (data.error) {
                    alert(`Hata: ${data.error}`);
                } else {
                    document.getElementById('rsa-public-key').value  = data.public_key;
                    document.getElementById('rsa-private-key').value = data.private_key;
                }
            } catch (err) {
                alert(`Bağlantı Hatası: ${err.message}`);
            } finally {
                btnRsaKeygen.innerHTML = originalHtml;
                btnRsaKeygen.disabled = false;
            }
        });
    }

    // --- HONEYPOT (SİBER TUZAK) MODÜLÜ MANTIĞI ---
    let honeypotPollInterval = null;
    let lastLogCount = 0;

    function showAttackerAlertPopup(logEntry) {
        const existing = document.getElementById('attacker-alert-overlay');
        if (existing) existing.remove();
        
        const overlay = document.createElement('div');
        overlay.id = 'attacker-alert-overlay';
        overlay.className = 'popup-overlay';
        overlay.style.zIndex = '80000';
        overlay.style.display = 'flex';
        
        overlay.innerHTML = `
            <div style="background: rgba(20, 5, 5, 0.98); padding: 3rem; border-radius: 1.5rem; text-align: center; border: 2px solid #ff3333; box-shadow: 0 0 50px rgba(255, 51, 51, 0.5); max-width: 500px; width: 90%; animation: aerodynamicFadeIn 0.25s ease-out; position: relative;">
                <div style="position: absolute; top: -10px; left: -10px; right: -10px; bottom: -10px; border-radius: 1.8rem; border: 1px solid rgba(255,51,51,0.25); pointer-events: none; animation: pulseAttackerGlow 1.5s infinite alternate;"></div>
                
                <i class="ti ti-alert-octagon" style="font-size: 4.5rem; color: #ff3333; margin-bottom: 1.5rem; filter: drop-shadow(0 0 15px #ff3333); display: inline-block;"></i>
                <h2 style="color: #ff3333; margin-bottom: 1rem; font-size: 1.6rem; letter-spacing: 0.05em; font-weight: 900; text-transform: uppercase;">⚠️ SIZMA GİRİŞİMİ ALGILANDI!</h2>
                
                <div style="background: rgba(255, 0, 0, 0.05); border: 1px solid rgba(255, 0, 0, 0.25); padding: 1.25rem; border-radius: 1rem; margin-bottom: 2rem;">
                    <p style="color: #fff; font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; font-weight: bold; margin: 0;">
                        ${logEntry.replace('[⚠️]', '').trim()}
                    </p>
                </div>
                
                <p style="color: var(--text-secondary); font-size: 0.88rem; line-height: 1.5; margin-bottom: 2rem;">
                    [TUZAK TETİKLENDİ] Saldırgan makine sahte servis bağlantısı üzerinden karantinaya alınmıştır.
                </p>
                
                <button id="btn-attacker-alert-close" class="btn-primary" style="background: #ff3333; color: #fff; font-weight: bold; width: 100%; justify-content: center; box-shadow: 0 0 15px rgba(255, 51, 51, 0.3);">Alarmı Sustur</button>
            </div>
        `;
        
        if (!document.getElementById('pulse-attacker-glow-style')) {
            const style = document.createElement('style');
            style.id = 'pulse-attacker-glow-style';
            style.innerHTML = `
                @keyframes pulseAttackerGlow {
                    from { transform: scale(1); opacity: 0.3; }
                    to { transform: scale(1.02); opacity: 0.8; }
                }
            `;
            document.head.appendChild(style);
        }
        
        document.body.appendChild(overlay);
        
        overlay.querySelector('#btn-attacker-alert-close').addEventListener('click', () => {
            overlay.style.animation = 'aerodynamicFadeOut 0.25s forwards';
            setTimeout(() => overlay.remove(), 250);
        });
    }

    function startHoneypotPolling() {
        if (honeypotPollInterval) clearInterval(honeypotPollInterval);
        honeypotPollInterval = setInterval(async () => {
            try {
                const response = await fetch('/api/honeypot/logs');
                const data = await response.json();
                
                const consoleEl = document.getElementById('honeypot-console');
                if (consoleEl) {
                    consoleEl.value = data.logs.join('\n');
                    consoleEl.scrollTop = consoleEl.scrollHeight;
                }
                
                if (data.logs.length > lastLogCount) {
                    for (let i = lastLogCount; i < data.logs.length; i++) {
                        const log = data.logs[i];
                        if (log.includes('[⚠️] Saldırgan Tespit Edildi!')) {
                            showAttackerAlertPopup(log);
                            appendChatMessage('System', `🚨 **TEHLİKE:** Yeni bir sızma girişimi algılandı!\n${log.replace('[⚠️]', '').trim()}`, 'system');
                        }
                    }
                    lastLogCount = data.logs.length;
                }
                
                const btnToggle = document.getElementById('btn-honeypot-toggle');
                if (btnToggle) {
                    if (data.active) {
                        btnToggle.innerHTML = '<i class="ti ti-square"></i> Siber Tuzak Durdur';
                        btnToggle.style.background = 'linear-gradient(135deg, var(--accent-magenta), #b91c1c)';
                    } else {
                        btnToggle.innerHTML = '<i class="ti ti-play"></i> Siber Tuzak Başlat';
                        btnToggle.style.background = 'linear-gradient(135deg, var(--accent-blue), #7c3aed)';
                        clearInterval(honeypotPollInterval);
                        honeypotPollInterval = null;
                    }
                }
            } catch (err) {
                console.error("Honeypot polling error:", err);
            }
        }, 1500);
    }

    const btnHoneypotToggle = document.getElementById('btn-honeypot-toggle');
    if (btnHoneypotToggle) {
        btnHoneypotToggle.addEventListener('click', async () => {
            const isRunning = btnHoneypotToggle.innerHTML.includes('Siber Tuzak Durdur');
            const port = document.getElementById('honeypot-port').value || 8080;
            
            try {
                if (isRunning) {
                    const response = await fetch('/api/honeypot/stop', { method: 'POST' });
                    const data = await response.json();
                    btnHoneypotToggle.innerHTML = '<i class="ti ti-play"></i> Siber Tuzak Başlat';
                    btnHoneypotToggle.style.background = 'linear-gradient(135deg, var(--accent-blue), #7c3aed)';
                    if (honeypotPollInterval) {
                        clearInterval(honeypotPollInterval);
                        honeypotPollInterval = null;
                    }
                    const consoleEl = document.getElementById('honeypot-console');
                    if (consoleEl) {
                        consoleEl.value += '\n[🟢] Honeypot kapatıldı.';
                        consoleEl.scrollTop = consoleEl.scrollHeight;
                    }
                } else {
                    const response = await fetch('/api/honeypot/start', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ port: parseInt(port) })
                    });
                    const data = await response.json();
                    
                    if (data.error) {
                        alert("HATA: " + data.error);
                        return;
                    }
                    
                    btnHoneypotToggle.innerHTML = '<i class="ti ti-square"></i> Siber Tuzak Durdur';
                    btnHoneypotToggle.style.background = 'linear-gradient(135deg, var(--accent-magenta), #b91c1c)';
                    lastLogCount = 0;
                    startHoneypotPolling();
                }
            } catch (err) {
                console.error("Honeypot toggle error:", err);
            }
        });
    }

});

