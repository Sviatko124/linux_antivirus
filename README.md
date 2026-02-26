# Linux Antivirus

A lightweight experimental antivirus for Linux combining Python for easy scripting and logic, and C for fast and efficient computations.

It can:

- Recursively scan directories
- Compute MD5 and SHA256 hashes using native C
- Compare hashes against a malware signature database
- Automatically quarantine detected files
- Run as a systemd service with real-time monitoring
- Log activity to `/var/log/antivirus.log`

This project was built as a learning exercise to learn:

- Python ↔ C integration (`ctypes`)
- Linux system programming
- systemd services
- filesystem monitoring
- malware hash detection concepts

---

# Features

### CLI scanner

Scan any folder manually:

```
python3 main_av_cli.py <folder> <signature_file> -v
```

Example:

```
python3 main_av_cli.py ~/Downloads signatures_sha256.txt -v
```


### Real-time protection (systemd service)

Monitors filesystem and automatically:

- detects malicious files
- removes execute permissions
- moves them to quarantine
- logs the event

Quarantine folder:

```
/var/lib/antivirus/quarantine
```

Log file:

```
/var/log/antivirus.log
```

Signature database location:

```
/var/lib/antivirus/signatures_sha256.txt
```

---

# Installation

## Clone repository

```
git clone https://github.com/sviatko124/linux-antivirus.git
cd linux-antivirus
```


## Install Python dependencies


Install libraries:

```
pip install -r requirements.txt
```


## Install required C libraries

```
sudo apt update
sudo apt install build-essential gcc libssl-dev python3-dev
```


## Compile C module

```
gcc -g -Wall -shared -fPIC modules.c -o modules.so -lssl -lcrypto
```


## Install antivirus service

```
chmod +x install_service.sh
sudo ./install_service.sh
```

---

# Signature database

Signature file:

```
/var/lib/antivirus/signatures_sha256.txt
```

Each line must contain one hash:

```
d47fb0d85e67ecacf03060780eee0770e6e06...
```

Recommended real malware hash database:

https://github.com/aaryanrlondhe/Malware-Hash-Database/tree/main

You can copy hashes into:

```
/var/lib/antivirus/signatures_sha256.txt
```

---

# Uninstall systemd service

```
chmod +x uninstall_service.sh
sudo ./uninstall_service.sh
```

---


# Security warning

This is a learning project and not production antivirus.

Limitations:

- Signature-only detection (no rootkit/heuristic detection)
- No automatic signature updates

Do **NOT** rely on this as real antivirus protection.

Use real antivirus software for security-critical systems.


---

# License

MIT License
