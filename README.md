<h1 align="center">OPEN-Eye</h1>
<p align="center">
  🕵️‍♂️ High-Performance TCP/UDP Port Scanner for Cybersecurity Professionals
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/Go-1.25.1-blue.svg" alt="Go Version"></a>
  <a href="https://github.com/CYBER-MRINAL/OPEN-Eye/stargazers"><img src="https://img.shields.io/github/stars/CYBER-MRINAL/OPEN-Eye?style=social" alt="GitHub Stars"></a>
  <a href="https://github.com/CYBER-MRINAL/OPEN-Eye/issues"><img src="https://img.shields.io/github/issues/CYBER-MRINAL/OPEN-Eye" alt="Issues"></a>
</p>

---

## 🚀 Overview

**OPEN-Eye** is a **professional, high-speed port scanner** built in Go. Designed for **penetration testers, red/blue teamers, and cybersecurity professionals**, it provides fast, reliable scanning for single hosts, multiple hosts, or entire CIDR ranges.

> Lightweight, fast, flexible, and output-ready for automation.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| ⚡ **High Performance** | Default 200 concurrent workers for lightning-fast scanning |
| 🔹 **Scan Types** | TCP (`connect`) & basic UDP scanning |
| 🖥️ **Flexible Targets** | Single host, host files, or CIDR ranges |
| 🔢 **Custom Ports** | Full range, top common ports, or custom lists |
| ⏱️ **Timeout & Retries** | Handles slow/unresponsive hosts gracefully |
| 🛑 **Rate Limiting** | Control connections per second to avoid flooding |
| 📊 **Multiple Outputs** | Table, CSV, JSON for automation & reporting |
| 📝 **Verbose Mode** | Detailed scanning progress and logs |
| 🏗️ **Standalone Binary** | No dependencies required; ready-to-run |

---

## 🛠️ Installation

```bash
# Clone repository
git clone https://github.com/CYBER-MRINAL/OPEN-Eye.git
cd OPEN-Eye

# Build binary
go build openeye.go (it is already build for furthure any issue this is a help line)

# Show available options
./openeye -h
````

---

## ⚙️ Usage

```bash
./openeye -host <target> [options]
```

### Common Options

| Flag            | Description                                        |
| --------------- | -------------------------------------------------- |
| `-T int`        | Number of concurrent workers (default 200)         |
| `-host string`  | Target host or IP (single)                         |
| `-hosts string` | File with hosts (one per line) or CIDR             |
| `-p string`     | Ports (e.g., 22,80,443 or 1-1024). Default: 1-1024 |
| `-top`          | Scan only top common ports                         |
| `-all`          | Show all ports (not only open)                     |
| `-s string`     | Scan type: `tcp` or `udp` (default tcp)            |
| `-timeout int`  | Timeout per port (seconds)                         |
| `-retries int`  | Retries per port on failure                        |
| `-rps int`      | Rate-limit connections per second                  |
| `-csv string`   | Export results to CSV file                         |
| `-json`         | Export results as JSON                             |
| `-v`            | Verbose output                                     |
| `-h`            | Show help                                          |

---

## 💡 Examples

**Scan ports 1-450 on a single host:**

```bash
./openeye -host wix.com -p 1-450
```

**Scan top common ports (fast):**

```bash
./openeye -host wix.com -top
```

**Scan all ports (1-1024):**

```bash
./openeye -host wix.com -all
```

**Scan multiple hosts from file and export JSON:**

```bash
./openeye -hosts targets.txt -json
```

**Scan multiple hosts and export CSV:**

```bash
./openeye -hosts targets.txt -csv results.csv
```

---

## 📊 Sample Output

```
[*] OPEN-Eye Scanner - targets: 1, results: 4, duration: 11.99s
+------------------------------+------+------+--------------+--------------------------------+
| Host                         | Port | Proto | Service     | Extra                        |
+------------------------------+------+------+--------------+--------------------------------+
| wix.com                      |   25 | tcp  | SMTP        |                                |
| wix.com                      |   53 | tcp  | DNS         |                                |
| wix.com                      |   80 | tcp  | HTTP        |                                |
| wix.com                      |  443 | tcp  | HTTPS       | CN=*.wix.com, Issuer=R13      |
+------------------------------+------+------+--------------+--------------------------------+
```

---

## 🔒 Why OPEN-Eye?

* ✅ **Fast & Efficient** – Scan hundreds of hosts concurrently
* ✅ **Professional Output** – JSON/CSV for automation and reporting
* ✅ **Customizable & Flexible** – Control ports, retries, timeout, and rate
* ✅ **Built for Professionals** – Ideal for pentesting & security audits

---

## 📂 License

Released under the **MIT License**. Free to use, modify, and distribute.
[View License](LICENSE)

---

## 👤 Author

**Mrinal Pramanick (CYBER-MRINAL)**

* GitHub: [CYBER-MRINAL](https://github.com/CYBER-MRINAL)
* Focus: Cybersecurity, penetration testing, network auditing, and professional security tools.

---

This version includes:

1. **Banner-style header** with icon.
2. **Badges** for license, Go version, GitHub stars, and issues.
3. **Feature highlight table** with icons for quick readability.
4. **Clean sections** for installation, usage, and examples.
5. **Professional callouts** for why OPEN-Eye is superior.
6. **Author section** linking to your GitHub.

---
