# ARP Scan Tool

** Currently this only works on linux. The windows version requires nping. Still working out the details

This is a cross-platform ARP scan tool written in Go. It works on Windows, Linux, and macOS without requiring any external dependencies or system modifications. The tool uses system utilities to scan for ARP entries and list the IP and MAC addresses of devices on the local network.

## Features
- **Platform-agnostic**: Works on Windows, Linux, and macOS.
- **No external dependencies**: Only uses Go's standard library and system utilities (e.g., `netsh` on Windows, `/proc/net/arp` on Linux, and `arp -a` on macOS).
- **Requires no elevated privileges**: Can be run without administrator or root access.

## Requirements
- **Go 1.20+** (or any recent version of Go)

## Compilation

To compile this tool for your operating system, follow the steps below:

### Windows:

1. **Open a terminal (Command Prompt or PowerShell)**.
2. **Navigate to the directory** where the source code is located.
3. **Run the following command** 
- to compile for Windows:
    `GOOS=windows GOARCH=amd64 go build -o arp-scan.exe`
- for Linux:
    `GOOS=linux GOARCH=amd64 go build -o arp-scan-mac`
- for MacOS:
    `GOOS=darwin GOARCH=amd64 go build -o arp-scan-mac`

