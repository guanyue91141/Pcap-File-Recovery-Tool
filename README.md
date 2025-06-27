# Network Traffic File Recovery Tool

A comprehensive Python tool for extracting and recovering files from network packet captures (PCAP files). Originally designed for digital forensics and CTF challenges, this tool can reconstruct files that were transferred, exfiltrated, or embedded within network traffic across multiple protocols.

## 🚀 Features

- **Multi-Protocol Support**: Extracts files from HTTP, FTP, SMTP, DNS, ICMP, and raw TCP streams
- **File Signature Detection**: Identifies files by their magic numbers (PNG, JPG, PDF, ZIP, EXE, etc.)
- **Covert Channel Detection**: Discovers data hidden in DNS queries and ICMP packets
- **HTTP Analysis**: Recovers uploaded files and downloaded content from HTTP traffic
- **Email Attachments**: Extracts attachments from SMTP email traffic
- **Comprehensive Reporting**: Detailed analysis reports with file metadata
- **Automatic Organization**: Saves recovered files with descriptive names and source information

## 📋 Requirements

- Python 3.6+
- Scapy library

### Installation

```bash
# Install required dependencies
pip install scapy

# Clone the repository
git clone https://github.com/yourusername/pcap-file-recovery.git
cd pcap-file-recovery

# Make the script executable (optional)
chmod +x file_recovery.py
```

## 🔧 Usage

### Basic Usage
```bash
# Analyze capture.pcapng (default filename)
python file_recovery.py

# The tool expects a file named 'capture.pcapng' in the same directory
```

### Input Requirements
- **PCAP File**: Place your packet capture file in the same directory as the script
- **Filename**: Rename your capture file to `capture.pcapng` or modify the script to use a different filename
- **Permissions**: Ensure read permissions on the PCAP file

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

## 🔍 Analysis Methods

### HTTP Traffic Analysis
- **File Downloads**: Extracts files from HTTP responses with `Content-Disposition` headers
- **File Uploads**: Recovers multipart form data uploads
- **Content-Type Detection**: Automatically assigns file extensions based on MIME types
- **Header Parsing**: Extracts original filenames when available

### FTP Traffic Analysis
- **Control Channel**: Monitors FTP commands to identify file transfers
- **Data Channel**: Captures file content from FTP data streams (ports 20/21)
- **Passive Mode**: Supports both active and passive FTP transfers

### Email (SMTP) Analysis
- **Attachment Extraction**: Recovers email attachments from SMTP traffic
- **Base64 Decoding**: Automatically decodes base64-encoded attachments
- **Filename Preservation**: Maintains original attachment filenames

### File Signature Detection
Identifies files by their magic number signatures:
- **Images**: PNG, JPG, GIF, BMP, ICO
- **Documents**: PDF, ZIP, RAR
- **Executables**: Windows PE (.exe), Linux ELF
- **Media**: WAV, MP3
- **Archives**: ZIP, RAR, GZIP

### Covert Channel Detection
- **DNS Exfiltration**: Detects hex-encoded data in DNS query names
- **ICMP Tunneling**: Identifies non-standard data in ICMP packets
- **TCP Stream Analysis**: Searches for file signatures across all TCP connections

## 📊 Example Output

```
=== Network Traffic File Recovery Tool ===
Analyzing: capture.pcapng
Loaded 15847 packets

[+] Analyzing HTTP traffic...
  [+] Recovered: document.pdf (245760 bytes) from HTTP Response
  [+] Recovered: http_file_0.bin (1024 bytes) from HTTP Response

[+] Analyzing FTP traffic...
  Found FTP upload: important_file.txt
  [+] Recovered: ftp_transfer_0.bin (2048 bytes) from FTP Transfer

[+] Analyzing SMTP traffic...
  [+] Recovered: attachment.docx (87552 bytes) from SMTP Attachment

[+] Analyzing TCP streams for file signatures...
  [+] Recovered: tcp_stream_45_0.png (156789 bytes) from TCP Stream (PNG)

[+] Checking for DNS exfiltration...
  [+] Recovered: dns_exfiltrated_data.bin (512 bytes) from DNS Exfiltration

[+] Checking ICMP packets for hidden data...
  [+] Recovered: icmp_hidden_data.bin (1536 bytes) from ICMP Covert Channel

============================================================
FILE RECOVERY REPORT
============================================================
Total files recovered: 15
Files saved to: recovered_files/

File: document.pdf
Size: 245760 bytes
Source: HTTP Response
Path: recovered_files/document.pdf
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
- **Reverse Engineering**: Recover original files for further analysis

### Network Security
- **DLP Monitoring**: Detect unauthorized file transfers
- **Policy Compliance**: Verify file transfer compliance
- **Threat Hunting**: Search for suspicious file activities
- **Baseline Analysis**: Understand normal file transfer patterns

## 🔧 Technical Details

### Supported File Types
| Category | Formats | Detection Method |
|----------|---------|------------------|
| Images | PNG, JPG, GIF, BMP, ICO | Magic number + boundary detection |
| Documents | PDF | Header/footer markers |
| Archives | ZIP, RAR, GZIP | Magic number signatures |
| Executables | PE (.exe), ELF | Platform-specific headers |
| Media | WAV, MP3 | Format-specific signatures |

### Protocol Support
| Protocol | Port(s) | Extraction Method |
|----------|---------|-------------------|
| HTTP | 80, 8080, etc. | Header parsing + content extraction |
| HTTPS | 443 | Limited (encrypted content) |
| FTP | 20, 21 | Command monitoring + data capture |
| SMTP | 25 | Email parsing + attachment extraction |
| DNS | 53 | Query analysis for exfiltration |
| ICMP | N/A | Payload analysis for covert channels |

### Performance Considerations
- **Memory Usage**: Processes large PCAP files efficiently
- **File Size Limits**: Automatically limits extracted files to 1MB for safety
- **Stream Reconstruction**: Properly reassembles fragmented TCP streams
- **Duplicate Handling**: Prevents duplicate file extraction

## 🛠️ Customization

### Modifying Input File
```python
# Change the default PCAP filename
pcap_file = "your_capture_file.pcap"
```

### Adding File Signatures
```python
# Add new file signatures to find_files_by_signature()
file_signatures = {
    b'\x42\x4D': ('BMP', b'\x42\x4D', None),  # BMP files
    # Add your custom signatures here
}
```

### Adjusting Output Directory
```python
# Change the output directory
self.output_dir = "custom_output_folder"
```

## 🚨 Troubleshooting

### Common Issues

**"Error loading PCAP" message**
- Verify the PCAP file exists and is readable
- Check if the file is corrupted with `tcpdump -r filename.pcap`
- Ensure sufficient permissions to read the file

**No files recovered**
- Verify the PCAP contains actual file transfers
- Check if traffic is encrypted (HTTPS/TLS)
- Try analyzing with Wireshark to confirm file transfers exist

**Permission denied errors**
- Run with appropriate user permissions
- Check write permissions in the current directory
- Ensure the output directory is writable

**Large PCAP files causing memory issues**
- Split large PCAP files using `tcpdump` or `editcap`
- Increase system memory or use a machine with more RAM
- Process specific time ranges or protocols

### Debugging Tips

1. **Use Wireshark**: First analyze the PCAP in Wireshark to understand the traffic
2. **Check Protocols**: Verify which protocols contain file transfers
3. **Examine Headers**: Look for Content-Disposition and Content-Type headers
4. **Test with Known Files**: Use a PCAP with known file transfers for testing

## 🤝 Contributing

Contributions are welcome! Here are ways you can help:

- **Add Protocol Support**: Implement extraction for additional protocols
- **Improve File Detection**: Add new file signature patterns
- **Enhance Error Handling**: Make the tool more robust
- **Performance Optimization**: Improve processing speed for large files
- **Documentation**: Help improve this README and code comments

### Development Setup
```bash
git clone https://github.com/yourusername/pcap-file-recovery.git
cd pcap-file-recovery

# Install development dependencies
pip install scapy pytest

# Run tests (if available)
python -m pytest tests/

# Test with sample PCAP
python file_recovery.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Tools

- **Wireshark**: Network protocol analyzer for manual PCAP analysis
- **tcpdump**: Command-line packet analyzer
- **NetworkMiner**: Network forensic analysis tool
- **Scapy**: Python packet manipulation library (used by this tool)
- **Foremost**: File carving tool for forensic analysis

## 📞 Support

If you encounter issues or have questions:

1. **Check the troubleshooting section** above
2. **Search existing issues** on GitHub
3. **Create a new issue** with:
   - Description of the problem
   - Sample PCAP file (if possible)
   - Error messages
   - System information

## 🏆 Acknowledgments

- **Scapy developers** for the excellent packet manipulation library
- **Digital forensics community** for file signature databases
- **CTF community** for creative file hiding techniques
- **Network security researchers** for covert channel detection methods

---

**Happy file hunting!** 🕵️‍♂️💾
