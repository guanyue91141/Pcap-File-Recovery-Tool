# Network Traffic File Recovery Tool

[![CI](https://github.com/d3vn0mi/Pcap-File-Recovery-Tool/actions/workflows/ci.yml/badge.svg)](https://github.com/d3vn0mi/Pcap-File-Recovery-Tool/actions/workflows/ci.yml)

A comprehensive Python tool for extracting and recovering files from network packet captures (PCAP files). Originally designed for digital forensics and CTF challenges, this tool can reconstruct files that were transferred, exfiltrated, or embedded within network traffic across multiple protocols.

## 🚀 Features

- **Multi-Protocol Support**: Extracts files from HTTP, FTP, SMTP, DNS, ICMP, and raw TCP streams
- **File Signature Detection**: Identifies files by their magic numbers (PNG, JPG, PDF, ZIP, EXE, etc.)
- **Covert Channel Detection**: Discovers data hidden in DNS queries and ICMP packets
- **HTTP Analysis**: Recovers uploaded files and downloaded content from HTTP traffic
- **Email Attachments**: Extracts attachments from SMTP email traffic
- **Hardened Against Hostile Captures**: Filenames carved from packet data are sanitized (no path traversal), carve sizes and file counts are capped, and malformed captures fail cleanly
- **Comprehensive Reporting**: Detailed analysis reports with file metadata
- **Automatic Organization**: Saves recovered files with descriptive names and source information

## 📋 Requirements

- Python 3.11+
- Scapy library (installed automatically)

## 📦 Installation

```bash
# Recommended: install as a CLI tool with pipx
pipx install git+https://github.com/d3vn0mi/Pcap-File-Recovery-Tool.git

# Or: clone and install into your environment
git clone https://github.com/d3vn0mi/Pcap-File-Recovery-Tool.git
cd Pcap-File-Recovery-Tool
pip install -e .
```

## 🔧 Usage

### Basic Usage

```bash
# Analyze a capture (defaults to capture.pcapng in the current directory)
pcap-file-recovery capture.pcapng

# Choose a different output directory
pcap-file-recovery evidence.pcap -o carved_output

# Also works as a module
python -m pcap_file_recovery capture.pcapng

# Legacy invocation (thin shim kept for compatibility)
python fire_recovery.py
```

> **Note on layout**: the implementation moved from a single `fire_recovery.py`
> script into a proper package under `src/pcap_file_recovery/`. The root-level
> `fire_recovery.py` is now a thin shim that calls the packaged CLI, so old
> muscle memory still works after `pip install -e .`.

### Input Requirements
- **PCAP File**: Pass the path to any libpcap/pcapng capture as the first argument
- **Default**: With no arguments the tool looks for `capture.pcapng` in the current directory
- **Permissions**: Ensure read permissions on the PCAP file and write permissions for the output directory

### Output Structure
```
recovered_files/
├── http_file_0.bin          # HTTP extracted files
├── http_file_1.bin
├── ftp_transfer_0.bin       # FTP transfers
├── signature_found_0.png    # Files found by signature
├── signature_found_1.pdf
├── dns_exfiltrated_data.bin # DNS exfiltration data
├── icmp_hidden_data.bin     # ICMP covert channel data
├── tcp_stream_83_0.bmp      # TCP stream extractions
└── recovery_summary.txt     # Detailed analysis report
```

## 🔍 How It Works

The tool loads the capture with Scapy, then runs seven extraction passes over the packets:

1. **HTTP**: parses response/upload headers, pulls filenames from `Content-Disposition`, carves the body after the header block
2. **FTP**: watches the control channel (port 21) for `STOR` commands and reassembles data-channel (port 20) streams
3. **SMTP**: finds `Content-Disposition: attachment` parts and base64-decodes them
4. **TCP streams**: groups payloads by connection 4-tuple and scans the reassembled stream for file signatures
5. **DNS**: decodes hex-encoded labels in query names (exfiltration detection)
6. **ICMP**: collects oversized echo payloads (covert channel detection)
7. **Signatures**: scans all raw payloads for magic numbers with header/footer carving

Every filename that originates from packet data is treated as hostile and reduced to a safe basename before anything is written to disk.

### File Signature Detection
Identifies files by their magic number signatures:
- **Images**: PNG, JPG, GIF, BMP, ICO
- **Documents**: PDF, ZIP, RAR
- **Executables**: Windows PE (.exe), Linux ELF
- **Media**: WAV, MP3
- **Archives**: ZIP, RAR, GZIP

## 📊 Example Output

```
=== Network Traffic File Recovery Tool ===
Analyzing: capture.pcapng
Loaded 15847 packets

[+] Analyzing HTTP traffic...
  [+] Recovered: document.pdf (245760 bytes) from HTTP Response

[+] Analyzing FTP traffic...
  Found FTP upload: important_file.txt
  [+] Recovered: ftp_transfer_0.bin (2048 bytes) from FTP Transfer

[+] Analyzing SMTP traffic...
  [+] Recovered: attachment.docx (87552 bytes) from SMTP Attachment

[+] Analyzing TCP streams for file signatures...
  [+] Recovered: tcp_stream_45_0.png (156789 bytes) from TCP Stream (PNG)

[+] Checking for DNS exfiltration...
  [+] Recovered: dns_exfiltrated_data.bin (512 bytes) from DNS Exfiltration

============================================================
FILE RECOVERY REPORT
============================================================
Total files recovered: 15
Files saved to: recovered_files/
```

## 🎯 Use Cases

### Digital Forensics
- **Incident Response**: Recover files transferred during security incidents
- **Data Exfiltration Analysis**: Identify what data was stolen during breaches
- **Network Evidence**: Extract files as evidence from packet captures
- **Malware Analysis**: Recover malicious files transferred over the network

### CTF Challenges
- **File Recovery**: Extract hidden flags from network captures
- **Protocol Analysis**: Understand how data was transmitted
- **Steganography**: Find files hidden in unexpected protocols

### Network Security
- **DLP Monitoring**: Detect unauthorized file transfers
- **Threat Hunting**: Search for suspicious file activities

## 🛡️ Security Hardening

This tool parses **untrusted input** by definition — captures often come straight from an attacker's traffic. The parser is hardened accordingly:

- **Filename sanitization**: names carved from `Content-Disposition` headers, multipart uploads, or SMTP attachments are stripped of path components, null bytes, and control characters before writing (no `../../` traversal, no absolute paths, no terminal escape injection)
- **No clobbering**: duplicate filenames get a numeric suffix instead of overwriting earlier evidence
- **Resource caps**: carves without an end marker are limited to 1 MB; total carved files are capped (default 1000) so a signature-bomb capture cannot exhaust disk or inodes
- **Graceful failure**: truncated captures, forged record-length fields, and non-pcap input are reported and exit cleanly instead of crashing mid-analysis
- **Sandboxing advice**: recovered files may be malware — analyze the output directory in an isolated environment

## 🧪 Development & Testing

```bash
git clone https://github.com/d3vn0mi/Pcap-File-Recovery-Tool.git
cd Pcap-File-Recovery-Tool

# Install with dev dependencies
pip install -e ".[dev]"

# Run the test suite (synthetic pcaps are built in code — no binary fixtures)
pytest

# Lint
ruff check .
```

CI runs `ruff check` and `pytest` on Python 3.11, 3.12, and 3.13 for every push and pull request.

### Project Layout
```
├── src/pcap_file_recovery/
│   ├── __init__.py          # Package exports
│   ├── __main__.py          # python -m pcap_file_recovery
│   ├── cli.py               # Argument parsing / console entry point
│   └── recovery.py          # FileRecoveryTool and carving logic
├── tests/                   # Pytest suite with in-code pcap fixtures
├── fire_recovery.py         # Backwards-compatible shim
└── pyproject.toml           # Packaging, ruff, and pytest configuration
```

## 🚨 Troubleshooting

**"Error loading PCAP" message**
- Verify the PCAP file exists and is readable
- Check if the file is corrupted with `tcpdump -r filename.pcap`

**No files recovered**
- Verify the PCAP contains actual file transfers
- Check if traffic is encrypted (HTTPS/TLS)
- Try analyzing with Wireshark to confirm file transfers exist

**Large PCAP files causing memory issues**
- The whole capture is loaded into memory by Scapy; split large PCAP files using `tcpdump` or `editcap`

## 🤝 Contributing

Contributions are welcome! Here are ways you can help:

- **Add Protocol Support**: Implement extraction for additional protocols
- **Improve File Detection**: Add new file signature patterns
- **Performance Optimization**: Improve processing speed for large files

Please make sure `pytest` and `ruff check .` pass before opening a pull request.

## ✍️ Author

**d3vn0mi** — [github.com/d3vn0mi](https://github.com/d3vn0mi)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Tools

- **Wireshark**: Network protocol analyzer for manual PCAP analysis
- **tcpdump**: Command-line packet analyzer
- **NetworkMiner**: Network forensic analysis tool
- **Scapy**: Python packet manipulation library (used by this tool)
- **Foremost**: File carving tool for forensic analysis

---

**Happy file hunting!** 🕵️‍♂️💾
