import subprocess
import webbrowser
import time
import os
import sys

def main():
    project_root = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(project_root, "venv", "Scripts", "python.exe")
    
    # Check if virtual environment python exists, fallback to system python
    if os.path.exists(venv_python):
        python_cmd = venv_python
    else:
        python_cmd = "python"
        
    print(f"Cyber Sentinel web sunucusu baslatiliyor...")
    print(f"Kullanilan Python: {python_cmd}")
    
    # Start the Flask app.py in a subprocess
    app_entry = os.path.join(project_root, "app.py")
    flask_process = subprocess.Popen([python_cmd, app_entry], cwd=project_root)
    
    # Wait for Flask server to bind to port 5000
    time.sleep(2.5)
    
    # Open the browser to the web app
    dashboard_url = "http://127.0.0.1:5000"
    print(f"Tarayici otomatik aciliyor: {dashboard_url}")
    webbrowser.open(dashboard_url)
    
    # Monitor the Flask process
    try:
        flask_process.wait()
    except KeyboardInterrupt:
        print("\nWeb sunucusu kapatiliyor...")
        flask_process.terminate()
        flask_process.wait()
        print("Sunucu durduruldu.")

if __name__ == "__main__":
    main()
