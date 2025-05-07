# GoFuzz - Web Directory & Subdomain Fuzzer 🔍

[![Go](https://img.shields.io/badge/Go-1.18%2B-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v2.1.2-blue.svg)](https://github.com/Lokidres/GoFuzz.go/releases)

Fast web fuzzer written in Go (source: `gofuzz.go`) for discovering hidden subdomains and directories.

## Features ✨
- 🚀 **Multi-threaded** scanning (adjustable concurrency)
- 🔍 **Dual-mode**: Subdomains (`-s`) + Directories (`-d`)
- 🎯 **Smart filtering** by status codes (`-f 200,302`)
- 📂 **File output** support (`-o results.txt`)
- 📊 **Verbose mode** for debugging (`-v`)

## Installation ⚙️
### Method 1: Direct Build
```bash
wget https://raw.githubusercontent.com/Lokidres/GoFuzz.go/main/gofuzz.go
go build -o gofuzz gofuzz.go
Method 2: Go Install
bash
go install github.com/Lokidres/GoFuzz.go@latest
Usage 🛠️
Basic Scan
bash
./gofuzz -u example.com -s subdomains.txt -d directories.txt -t 20
Advanced Example
bash
./gofuzz -u https://target.com -s subs.txt -f 200,403 -o found.txt -v
All Options
Flag	Description	Default
-u	Target URL (required)	-
-s	Subdomain wordlist	-
-d	Directory wordlist	-
-t	Threads (concurrency)	10
-timeout	Request timeout (seconds)	10
-f	Filter status codes (e.g. 200,302)	-
-v	Verbose output	false
Sample Output 📄
plaintext
https://admin.target.com [200] (Size: 2.1KB)
https://dev.target.com [302] → https://target.com/login
http://test.target.com/api [403] (Size: 512B)
Wordlists 📚
Recommended wordlists:

SecLists

AssetNote Wordlists

FuzzDB

Building from Source 🛠️
bash
# Linux
GOOS=linux go build -o gofuzz gofuzz.go

# Windows
GOOS=windows go build -o gofuzz.exe gofuzz.go

# macOS
GOOS=darwin go build -o gofuzz gofuzz.go
License 📜
MIT License - See LICENSE file.

🔐 Note: Always get proper authorization before scanning any website.
Maintained by Lokidres.
