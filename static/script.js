document.addEventListener('DOMContentLoaded', () => {
    
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

    if (disclaimerModal && disclaimerCheck && btnAcceptDisclaimer) {
        if (localStorage.getItem('disclaimer_accepted') === 'true') {
            disclaimerModal.style.display = 'none';
            autoOpenChatWidget();
        } else {
            disclaimerModal.style.display = 'flex';
        }

        disclaimerCheck.addEventListener('change', () => {
            btnAcceptDisclaimer.disabled = !disclaimerCheck.checked;
        });

        btnAcceptDisclaimer.addEventListener('click', () => {
            localStorage.setItem('disclaimer_accepted', 'true');
            disclaimerModal.style.animation = 'aerodynamicFadeOut 0.5s forwards';
            setTimeout(() => {
                disclaimerModal.style.display = 'none';
                autoOpenChatWidget();
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

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            if (typeof isStationActive !== 'undefined' && !isStationActive) {
                document.getElementById('warn-popup').style.display = 'flex';
                return;
            }
            navItems.forEach(nav => nav.classList.remove('active'));
            tabContents.forEach(tab => tab.classList.remove('active'));
            item.classList.add('active');
            document.getElementById(item.dataset.tab).classList.add('active');
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

    // --- DoS STRES TESTİ EVENT HANDLER ---
    document.getElementById('btn-stresstest').addEventListener('click', () => {
        const targetUrl = document.getElementById('stress-target').value.trim();
        const reqCount = document.getElementById('stress-count').value.trim();
        
        if (!targetUrl) return;
        
        document.getElementById('stress-stats-panel').style.display = 'none';
        document.getElementById('stress-chart-card').style.display = 'none';
        
        postApi('/api/security/stress-test', {target: targetUrl, count: reqCount}, 'btn-stresstest', 'stress-results', (data) => {
            if (data.error) {
                return addLog('stress-results', data.error, 'error');
            }
            
            addLog('stress-results', `<b>[+] STRES TESTİ BAŞARIYLA TAMAMLANDI</b>`, 'success', true);
            addLog('stress-results', `Hedef URL: ${data.target}`, 'info');
            addLog('stress-results', `Toplam Gönderilen İstek: ${data.total_requests}`, 'info');
            addLog('stress-results', `Başarılı Yanıtlar: <span class="status-up">${data.success}</span> | Hatalı Yanıtlar: <span class="status-down">${data.errors}</span>`, 'none', true);
            addLog('stress-results', `Ortalama Gecikme: ${data.avg_latency} ms (Min: ${data.min_latency} ms | Maks: ${data.max_latency} ms)`, 'info');
            addLog('stress-results', `Toplam Test Süresi: ${data.total_duration_ms} ms`, 'info');
            
            // Eğer anomali varsa logla
            if (data.anomalies && data.anomalies.length > 0) {
                addLog('stress-results', `<b>⚠️ Sunucuda Tespit Edilen Kararsızlıklar / Anomaliler:</b>`, 'error', true);
                data.anomalies.forEach(anomaly => {
                    addLog('stress-results', `<span class="status-down">${anomaly}</span>`, 'none', true);
                });
            } else {
                addLog('stress-results', `[+] Test süresince sunucu kararlı çalıştı. Herhangi bir anomali tespit edilmedi.`, 'success');
            }

            // Stats panelini güncelle ve görünür yap
            document.getElementById('stress-stat-avg').textContent = `${data.avg_latency} ms`;
            document.getElementById('stress-stat-success-fail').textContent = `${data.success} / ${data.errors}`;
            document.getElementById('stress-stat-maxmin').textContent = `${data.max_latency} / ${data.min_latency} ms`;
            
            const riskEl = document.getElementById('stress-stat-risk');
            riskEl.textContent = `${data.risk_percentage}% - ${data.risk_level.split(' ')[0]}`;
            riskEl.style.color = data.risk_color;
            
            document.getElementById('stress-stats-panel').style.display = 'block';
            
            // Grafiği çiz ve görünür yap
            document.getElementById('stress-chart-card').style.display = 'flex';
            drawLatencyBarChart('stress-chart', data.latencies);
            
            document.getElementById('btn-ai-stress').style.display = 'inline-flex';
        });
    });

    // 14. Güvenli Kod Analizi (SAST)
    document.getElementById('btn-sast').addEventListener('click', () => {
        const codeVal = document.getElementById('sast-code').value;
        if (!codeVal.trim()) return;
        
        postApi('/api/security/code-scan', {target: codeVal}, 'btn-sast', 'sast-results', (data) => {
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
                <h2 class="whoami-title"><i class="ti ti-info-circle"></i> Ben Kimim? / Uygulama Profili</h2>
                <button id="btn-whoami-close-top" class="btn-primary" style="background: rgba(255,255,255,0.09); color: #fff; box-shadow: none;">Kapat</button>
            </div>
            <div class="whoami-grid">
                <div class="whoami-card">
                    <h4>Uygulamanın Konusu</h4>
                    <p>Bu platform, ağ güvenliği ve siber keşif süreçlerini tek panelde birleştiren interaktif bir operasyon istasyonudur. Ping, port, DNS, WiFi ve web güvenlik testleriyle hızlı analiz sağlar.</p>
                </div>
                <div class="whoami-card">
                    <h4>Çalışma Prensibi</h4>
                    <p>Kullanıcıdan alınan hedef bilgileri, arka uç API servisleri üzerinden kontrollü tarama modüllerine yönlendirilir. Sonuçlar eş zamanlı olarak görsel log kartlarında sunulur ve operasyonel karar desteği oluşturur.</p>
                </div>
                <div class="whoami-card">
                    <h4>Misyon</h4>
                    <p>Ağ ve sistem güvenliği farkındalığını artırmak; temel keşif ve analiz adımlarını erişilebilir, anlaşılır ve hızlı hale getirerek teknik kullanıcıya pratik bir kontrol merkezi sunmak.</p>
                </div>
                <div class="whoami-card">
                    <h4>Vizyon</h4>
                    <p>Modern, aero-dinamik ve yenilikçi arayüz yaklaşımıyla; ileri düzey tehdit görünürlüğü, akıllı otomasyon ve gerçek zamanlı güvenlik telemetrisi sağlayan bütünleşik bir siber savunma paneline dönüşmek.</p>
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

    powerBtn.addEventListener('click', () => {
        if (isBooting) return; // Prevent clicking during boot

        if (isStationActive) {
            // Shutdown System
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
                    isStationActive = true;
                    
                    overlay.style.display = 'none';
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
            }, 1000);
        }
    });

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

    // ─────────────────────────────────────────────────────────────
    // OTURUM & ÇEREZ ANALİZİ (CANLI KONSOL VE POLLING)
    // ─────────────────────────────────────────────────────────────
    const btnSessionCookie = document.getElementById('btn-session-cookie');
    const sessionCookieConsole = document.getElementById('session-cookie-console');
    const sessionCookieTarget = document.getElementById('session-cookie-target');
    let pollingInterval = null;

    if (btnSessionCookie) {
        btnSessionCookie.addEventListener('click', async () => {
            const targetUrl = sessionCookieTarget.value.trim();
            if (!targetUrl) {
                alert('Lütfen analiz edilecek bir URL girin.');
                return;
            }

            // Temizleme ve yükleme durumunu başlatma
            sessionCookieConsole.value = '';
            sessionCookieConsole.value += "=========================================================\n";
            sessionCookieConsole.value += "[*] Oturum & Çerez Güvenliği Analiz Modülü Başlatılıyor...\n";
            sessionCookieConsole.value += "=========================================================\n";
            
            const originalHtml = btnSessionCookie.innerHTML;
            btnSessionCookie.innerHTML = '<span class="loader" style="width:15px;height:15px;border-width:2px;"></span> BAŞLADI';
            btnSessionCookie.disabled = true;

            try {
                const response = await fetch('/api/security/cookie-analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: targetUrl })
                });
                const data = await response.json();

                if (data.error) {
                    sessionCookieConsole.value += `[Hata]: ${data.error}\n`;
                    btnSessionCookie.innerHTML = originalHtml;
                    btnSessionCookie.disabled = false;
                    return;
                }

                const analysisId = data.analysis_id;
                let lastLogIndex = 0;

                // Her 450ms'de bir logları çek
                pollingInterval = setInterval(async () => {
                    try {
                        const logResponse = await fetch(`/api/security/cookie-analyze/logs/${analysisId}`);
                        const logData = await logResponse.json();

                        if (logData.error) {
                            sessionCookieConsole.value += `[Hata]: Loglar alınamadı: ${logData.error}\n`;
                            clearInterval(pollingInterval);
                            btnSessionCookie.innerHTML = originalHtml;
                            btnSessionCookie.disabled = false;
                            return;
                        }

                        const logs = logData.logs || [];
                        // Sadece yeni gelen satırları yazdır
                        if (logs.length > lastLogIndex) {
                            for (let i = lastLogIndex; i < logs.length; i++) {
                                sessionCookieConsole.value += logs[i] + '\n';
                            }
                            lastLogIndex = logs.length;
                            // Konsolu en alta kaydır
                            sessionCookieConsole.scrollTop = sessionCookieConsole.scrollHeight;
                        }

                        if (logData.done) {
                            clearInterval(pollingInterval);
                            btnSessionCookie.innerHTML = originalHtml;
                            btnSessionCookie.disabled = false;
                        }
                    } catch (err) {
                        sessionCookieConsole.value += `[Hata]: Bağlantı kesildi: ${err.message}\n`;
                        clearInterval(pollingInterval);
                        btnSessionCookie.innerHTML = originalHtml;
                        btnSessionCookie.disabled = false;
                    }
                }, 450);

            } catch (error) {
                sessionCookieConsole.value += `[Hata]: İstek başarısız oldu: ${error.message}\n`;
                btnSessionCookie.innerHTML = originalHtml;
                btnSessionCookie.disabled = false;
            }
        });
    }

});

