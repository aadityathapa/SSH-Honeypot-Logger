import subprocess
import sys
import time

def main():
    honeypot = subprocess.Popen([sys.executable, "honeypot.py"])
    time.sleep(1) # lets honeypot start up first

    try:
        subprocess.run([sys.executable, "dashboard.py"])
    except KeyboardInterrupt:
        pass
    finally:
        honeypot.terminate()
        print("\n[+] Honeypot stopped.")

if __name__ == "__main__":
    main()


