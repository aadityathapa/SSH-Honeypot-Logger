# 🍯 SSH Honeypot

A fake SSH server that logs every login attempt, with a live terminal dashboard.

## Install dependencies

```bash
pip install paramiko rich
```

## Run it

**Terminal 1 — start the honeypot:**
```bash
python3 honeypot.py
```
> Listens on port **2222** by default (no root needed).  
> To use port 22 (standard SSH), run with `sudo` and change `PORT = 22` in `honeypot.py`.

**Terminal 2 — open the live dashboard:**
```bash
python3 dashboard.py
```

**Or, just run the start script**
```bash
python3 start.py
```

## Test it yourself

```bash
ssh -p 2222 root@localhost
# enter any password — it will always fail, but it gets logged
```

## What gets logged

Every attempt is saved to `honeypot.db` (SQLite) and `honeypot.log`:

| Field    | Example              |
|----------|----------------------|
| Time     | 2024-01-15T10:23:45  |
| IP       | 203.0.113.42         |
| Username | root                 |
| Password | 123456               |

## Expose it to the internet (optional, advanced)

If you have a cloud VM or open port 2222 on your router, real bots will find it within hours.

```bash
# On a server, run on port 22 (requires root or authbind)
sudo python3 honeypot.py  # after changing PORT = 22
```

⚠️ **Safety notes:**
- The honeypot never grants real access — it always returns `AUTH_FAILED`
- Run it in a VM or container if exposing to the internet
- Don't run on your main machine's port 22 (that's your real SSH!)

## Project ideas to extend it

- 🌍 **GeoIP map** — plot attacker IPs on a world map
- 📊 **Attack timeline** — chart attempts over time with matplotlib
- 🔔 **Alerts** — send a notification when a new IP appears
- 🤖 **Fake shell** — instead of rejecting, let attackers "in" to a fake shell and log commands
