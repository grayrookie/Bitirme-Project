# Electron Windows Build

Bu proje Electron ile masaustu uygulamasina donusturuldu.

## Eklenenler

- `main.js`: Electron ana sureci, Flask backend'i otomatik baslatir.
- `package.json`: Electron ve `electron-builder` konfigurasyonu.
- Windows hedefleri: `nsis` (kurulum sihirbazi) ve `portable`.

## Gereksinim

- Node.js LTS (npm ile birlikte)
- Python venv klasoru (`venv`) proje kokunde mevcut olmali

## Calistirma

```powershell
npm install
npm start
```

## Windows `.exe` cikti alma

```powershell
npm run dist
```

Ciktilar:

- `dist/Cyber Sentinel-Setup-1.0.0.exe` (NSIS kurulum paketi)
- `dist/Cyber Sentinel-Setup-1.0.0.exe` benzeri adla portable hedef

## Tek dosya portable (onerilen)

Kurulum istemiyorsan sadece tasinabilir tek `.exe` cikarmak icin:

```powershell
npm run dist:portable:single
```

Beklenen cikti:

- `dist/Cyber Sentinel-Portable-1.0.0.exe`

## Ikon ve metadata

Windows uygulama ikonu ve metadata ayarlari eklendi.

Yapman gereken:

1. `build/icon.ico` dosyasini koy
2. Build al

```powershell
npm run dist:portable:single
```

Not: `build/icon.ico` yoksa electron-builder ikonla ilgili hata verebilir.

