const { app, BrowserWindow, dialog } = require("electron");
const { spawn } = require("child_process");
const path = require("path");
const http = require("http");

let mainWindow = null;
let backendProcess = null;

const HOST = "127.0.0.1";
const PORT = 5000;
const APP_URL = `http://${HOST}:${PORT}`;

function getPythonCommand() {
    const projectRoot = __dirname;
    const venvPython = path.join(projectRoot, "venv", "Scripts", "python.exe");
    const pyLauncher = "py";
    return { venvPython, pyLauncher };
}

function spawnBackend() {
    const projectRoot = __dirname;
    const { venvPython, pyLauncher } = getPythonCommand();
    
    // Path to standalone executable in production
    let exePath = path.join(projectRoot, "backend", "app.exe");
    if (exePath.includes("app.asar")) {
        exePath = exePath.replace("app.asar", "app.asar.unpacked");
    }
    const fs = require("fs");

    if (fs.existsSync(exePath)) {
        // Run standalone backend exe in production
        backendProcess = spawn(exePath, [], {
            cwd: path.dirname(exePath),
            windowsHide: true,
            stdio: "ignore",
        });
    } else {
        // Fallback to python scripts in development
        const appEntry = path.join(projectRoot, "app.py");
        backendProcess = spawn(venvPython, [appEntry], {
            cwd: projectRoot,
            windowsHide: true,
            stdio: "ignore",
        });

        backendProcess.on("error", () => {
            backendProcess = spawn(pyLauncher, ["app.py"], {
                cwd: projectRoot,
                windowsHide: true,
                stdio: "ignore",
            });
        });
    }
}

function waitForServer(url, timeoutMs = 30000) {
    const start = Date.now();

    return new Promise((resolve, reject) => {
        const check = () => {
            const req = http.get(url, (res) => {
                res.resume();
                if (res.statusCode && res.statusCode < 500) {
                    resolve(true);
                } else if (Date.now() - start > timeoutMs) {
                    reject(new Error("Backend timeout"));
                } else {
                    setTimeout(check, 600);
                }
            });

            req.on("error", () => {
                if (Date.now() - start > timeoutMs) {
                    reject(new Error("Backend timeout"));
                } else {
                    setTimeout(check, 600);
                }
            });

            req.setTimeout(2000, () => {
                req.destroy();
            });
        };

        check();
    });
}

async function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1366,
        height: 860,
        minWidth: 1180,
        minHeight: 760,
        backgroundColor: "#050505",
        autoHideMenuBar: true,
        title: "Cyber Sentinel",
        webPreferences: {
            contextIsolation: true,
            sandbox: true,
            devTools: false,
        },
    });

    spawnBackend();

    try {
        await waitForServer(APP_URL, 35000);
        await mainWindow.loadURL(APP_URL);
    } catch (error) {
        dialog.showErrorBox(
            "Başlatma Hatası",
            "Backend servisi başlatılamadı. Python/venv kurulumunu kontrol edin."
        );
        app.quit();
    }
}

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
    if (backendProcess && !backendProcess.killed) {
        backendProcess.kill();
    }
    if (process.platform !== "darwin") {
        app.quit();
    }
});

app.on("before-quit", () => {
    if (backendProcess && !backendProcess.killed) {
        backendProcess.kill();
    }
});

