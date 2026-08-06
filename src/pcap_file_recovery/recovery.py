#!/usr/bin/env python3
"""
Network Traffic File Recovery Tool

This module analyzes network traffic to recover files that may have been
exfiltrated or transferred during an attack. It extracts files from various
protocols and reconstructs them from network streams.

All input is treated as hostile: the capture file, and every filename or
length field carved out of packet data, comes from the wire and must never
be trusted.
"""

import base64
import binascii
import os
import re
import sys
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, Packet, Raw, rdpcap

# Conservative allow-list for characters in recovered filenames.
_UNSAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")
# Control characters that must never reach the terminal or a filename.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

MAX_FILENAME_LENGTH = 120
RECOVERY_SUMMARY_NAME = "recovery_summary.txt"


def sanitize_filename(filename: str) -> str:
    """Reduce an untrusted, network-supplied filename to a safe basename.

    Strips directory components (path traversal), null bytes, control
    characters and anything outside a conservative allow-list, so a name
    carved out of packet data can never escape the output directory.
    """
    filename = filename.replace("\x00", "").replace("\\", "/")
    filename = filename.rsplit("/", 1)[-1]
    filename = _UNSAFE_CHARS_RE.sub("_", filename)
    filename = filename.lstrip(".")
    if not filename:
        filename = "unnamed"
    if len(filename) > MAX_FILENAME_LENGTH:
        root, dot, ext = filename.rpartition(".")
        if dot and root and len(ext) <= 10:
            filename = root[: MAX_FILENAME_LENGTH - len(ext) - 1] + "." + ext
        else:
            filename = filename[:MAX_FILENAME_LENGTH]
    return filename


def _printable(text: str) -> str:
    """Strip control characters from untrusted text before printing it."""
    return _CONTROL_CHARS_RE.sub("", text)


class FileRecoveryTool:
    def __init__(self, pcap_file: str, output_dir: str = "recovered_files", max_files: int = 1000) -> None:
        self.pcap_file = pcap_file
        self.recovered_files: list[dict[str, object]] = []
        self.output_dir = output_dir
        # Cap on carved files so a crafted capture full of magic numbers
        # cannot exhaust disk space or inodes.
        self.max_files = max_files
        # Cap for carves that have no end-of-file marker.
        self.max_carve_size = 1024 * 1024  # 1MB
        self._max_files_warned = False
        self.create_output_directory()

    def create_output_directory(self) -> None:
        """Create directory for recovered files"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"Created output directory: {self.output_dir}")

    def analyze_traffic(self) -> bool:
        """Main analysis function. Returns False if the capture could not be loaded."""
        print("=== Network Traffic File Recovery Tool ===")
        print(f"Analyzing: {self.pcap_file}")

        try:
            packets = rdpcap(self.pcap_file)
            print(f"Loaded {len(packets)} packets")
        except Exception as e:
            # rdpcap parses a hostile file and can raise a wide range of
            # exceptions on corrupt input; report and bail out cleanly.
            print(f"Error loading PCAP: {e}")
            return False

        # Analyze different protocols
        self.extract_http_files(packets)
        self.extract_ftp_files(packets)
        self.extract_smtp_files(packets)
        self.extract_tcp_streams(packets)
        self.extract_dns_exfiltration(packets)
        self.extract_icmp_data(packets)
        self.search_file_signatures(packets)

        self.generate_report()
        return True

    def extract_http_files(self, packets: Iterable[Packet]) -> None:
        """Extract files from HTTP traffic"""
        print("\n[+] Analyzing HTTP traffic...")

        for packet in packets:
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                payload = packet[Raw].load

                # Look for HTTP responses with file content
                if b"HTTP/" in payload and (b"Content-Type:" in payload or b"Content-Disposition:" in payload):
                    self.extract_http_response(payload)

                # Look for file uploads
                if b"Content-Disposition: form-data" in payload:
                    self.extract_http_upload(payload)

    def extract_http_response(self, payload: bytes) -> None:
        """Extract files from HTTP responses"""
        payload_str = payload.decode("utf-8", errors="ignore")

        # Extract filename from Content-Disposition header
        filename = None
        content_disp_match = re.search(r"Content-Disposition:.*filename[*]?=([^;\r\n]+)", payload_str, re.IGNORECASE)
        if content_disp_match:
            filename = content_disp_match.group(1).strip("\"'")

        # Extract content type
        content_type_match = re.search(r"Content-Type:\s*([^\r\n]+)", payload_str, re.IGNORECASE)
        content_type = content_type_match.group(1) if content_type_match else "unknown"

        # Find the start of file content (after headers)
        header_end = payload.find(b"\r\n\r\n")
        if header_end != -1:
            file_content = payload[header_end + 4:]

            if filename:
                self.save_recovered_file(filename, file_content, "HTTP Response")
            else:
                # Generate filename based on content type
                ext = self.get_extension_from_content_type(content_type)
                filename = f"http_file_{len(self.recovered_files)}.{ext}"
                self.save_recovered_file(filename, file_content, "HTTP Response")

    def extract_http_upload(self, payload: bytes) -> None:
        """Extract files from HTTP uploads"""
        payload_str = payload.decode("utf-8", errors="ignore")

        # Look for multipart form data
        boundary_match = re.search(r"boundary=([^\r\n]+)", payload_str)
        if boundary_match:
            boundary = boundary_match.group(1)

            # Split by boundary
            parts = payload.split(boundary.encode())

            for part in parts:
                if b"Content-Disposition: form-data" in part and b"filename=" in part:
                    filename_match = re.search(rb'filename="([^"]+)"', part)
                    if filename_match:
                        filename = filename_match.group(1).decode("utf-8", errors="ignore")

                        # Find file content
                        content_start = part.find(b"\r\n\r\n")
                        if content_start != -1:
                            file_content = part[content_start + 4:]
                            self.save_recovered_file(filename, file_content, "HTTP Upload")

    def extract_ftp_files(self, packets: Iterable[Packet]) -> None:
        """Extract files from FTP traffic"""
        print("\n[+] Analyzing FTP traffic...")

        ftp_data_streams: dict[str, list[bytes]] = defaultdict(list)

        for packet in packets:
            if packet.haslayer(TCP):
                # FTP control channel (port 21)
                if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                    if packet.haslayer(Raw):
                        payload = packet[Raw].load.decode("utf-8", errors="ignore")

                        # Look for STOR command (file upload)
                        if "STOR " in payload:
                            filename = payload.split("STOR ")[1].strip()
                            print(f"  Found FTP upload: {_printable(filename)}")

                # FTP data channel (port 20 or passive mode)
                elif packet[TCP].dport == 20 or packet[TCP].sport == 20:
                    if packet.haslayer(Raw) and packet.haslayer(IP):
                        # This is likely file data
                        stream_id = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
                        ftp_data_streams[stream_id].append(packet[Raw].load)

        # Save FTP data streams
        for i, chunks in enumerate(ftp_data_streams.values()):
            filename = f"ftp_transfer_{i}.bin"
            self.save_recovered_file(filename, b"".join(chunks), "FTP Transfer")

    def extract_smtp_files(self, packets: Iterable[Packet]) -> None:
        """Extract email attachments from SMTP traffic"""
        print("\n[+] Analyzing SMTP traffic...")

        for packet in packets:
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                if packet[TCP].dport == 25 or packet[TCP].sport == 25:
                    payload_str = packet[Raw].load.decode("utf-8", errors="ignore")

                    # Look for email attachments
                    if "Content-Disposition: attachment" in payload_str:
                        filename_match = re.search(r'filename="([^"]+)"', payload_str)
                        if filename_match:
                            filename = filename_match.group(1)

                            # Extract base64 encoded content
                            lines = payload_str.split("\n")
                            in_attachment = False
                            attachment_data = []

                            for line in lines:
                                if "Content-Transfer-Encoding: base64" in line:
                                    in_attachment = True
                                elif in_attachment and line.strip() and not line.startswith("--"):
                                    attachment_data.append(line.strip())
                                elif in_attachment and line.startswith("--"):
                                    break

                            if attachment_data:
                                try:
                                    decoded_data = base64.b64decode("".join(attachment_data))
                                except (binascii.Error, ValueError) as e:
                                    print(f"  [-] Skipping attachment with invalid base64: {e}", file=sys.stderr)
                                else:
                                    self.save_recovered_file(filename, decoded_data, "SMTP Attachment")

    def extract_tcp_streams(self, packets: Iterable[Packet]) -> None:
        """Extract files from TCP streams by looking for file signatures"""
        print("\n[+] Analyzing TCP streams for file signatures...")

        tcp_streams: dict[tuple, list[bytes]] = defaultdict(list)

        for packet in packets:
            if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
                # Group by TCP stream
                stream_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
                tcp_streams[stream_key].append(packet[Raw].load)

        # Analyze each stream
        for i, data_list in enumerate(tcp_streams.values()):
            stream_data = b"".join(data_list)

            # Look for file signatures in the stream
            files_found = self.find_files_by_signature(stream_data)

            for j, (file_data, file_type) in enumerate(files_found):
                filename = f"tcp_stream_{i}_{j}.{file_type.lower()}"
                self.save_recovered_file(filename, file_data, f"TCP Stream ({file_type})")

    def extract_dns_exfiltration(self, packets: Iterable[Packet]) -> None:
        """Extract data exfiltrated via DNS"""
        print("\n[+] Checking for DNS exfiltration...")

        dns_data: list[bytes] = []

        for packet in packets:
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname
                query = qname.decode("utf-8", errors="ignore") if isinstance(qname, bytes) else str(qname)

                # Look for hex-encoded data in DNS queries
                parts = query.split(".")
                for part in parts:
                    if len(part) > 4 and re.match(r"^[0-9a-fA-F]+$", part):
                        try:
                            dns_data.append(binascii.unhexlify(part))
                        except binascii.Error:
                            # Odd-length label; not valid hex payload data.
                            continue

        if dns_data:
            combined_data = b"".join(dns_data)
            self.save_recovered_file("dns_exfiltrated_data.bin", combined_data, "DNS Exfiltration")

    def extract_icmp_data(self, packets: Iterable[Packet]) -> None:
        """Extract data from ICMP packets (covert channel)"""
        print("\n[+] Checking ICMP packets for hidden data...")

        icmp_data: list[bytes] = []

        for packet in packets:
            if packet.haslayer(ICMP) and packet.haslayer(Raw):
                payload = packet[Raw].load

                # ICMP data that's not standard ping data might be exfiltrated content
                if len(payload) > 8:  # Standard ping is usually 8 bytes or less
                    icmp_data.append(payload)

        if icmp_data:
            combined_data = b"".join(icmp_data)
            self.save_recovered_file("icmp_hidden_data.bin", combined_data, "ICMP Covert Channel")

    def search_file_signatures(self, packets: Iterable[Packet]) -> None:
        """Search for file signatures across all packet payloads"""
        print("\n[+] Searching for file signatures in packet payloads...")

        all_data = b"".join(packet[Raw].load for packet in packets if packet.haslayer(Raw))

        # Find files by signature
        files_found = self.find_files_by_signature(all_data)

        for i, (file_data, file_type) in enumerate(files_found):
            filename = f"signature_found_{i}.{file_type.lower()}"
            self.save_recovered_file(filename, file_data, f"File Signature ({file_type})")

    def find_files_by_signature(self, data: bytes) -> list[tuple[bytes, str]]:
        """Find files in data by their magic number signatures"""
        file_signatures: dict[bytes, tuple[str, bytes, bytes | None]] = {
            b"\x89PNG\r\n\x1a\n": ("PNG", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
            b"\xff\xd8\xff": ("JPG", b"\xff\xd8\xff", b"\xff\xd9"),
            b"GIF8": ("GIF", b"GIF8", b"\x00\x3b"),
            b"%PDF": ("PDF", b"%PDF", b"%%EOF"),
            b"PK\x03\x04": ("ZIP", b"PK\x03\x04", b"PK\x05\x06"),
            b"Rar!": ("RAR", b"Rar!", None),
            b"\x1f\x8b\x08": ("GZ", b"\x1f\x8b\x08", None),
            b"BM": ("BMP", b"BM", None),
            b"\x00\x00\x01\x00": ("ICO", b"\x00\x00\x01\x00", None),
            b"RIFF": ("WAV", b"RIFF", None),
            b"\x49\x44\x33": ("MP3", b"\x49\x44\x33", None),
            b"\x4d\x5a": ("EXE", b"\x4d\x5a", None),
            b"\x7f\x45\x4c\x46": ("ELF", b"\x7f\x45\x4c\x46", None),
        }

        found_files: list[tuple[bytes, str]] = []

        for signature, (file_type, _start_sig, end_sig) in file_signatures.items():
            start_pos = 0

            while True:
                pos = data.find(signature, start_pos)
                if pos == -1:
                    break

                if end_sig:
                    end_pos = data.find(end_sig, pos + len(signature))
                    if end_pos != -1:
                        file_data = data[pos:end_pos + len(end_sig)]
                        found_files.append((file_data, file_type))
                        start_pos = end_pos + len(end_sig)
                    else:
                        # Take a reasonable chunk if no end signature found
                        file_data = data[pos:pos + min(self.max_carve_size, len(data) - pos)]
                        found_files.append((file_data, file_type))
                        start_pos = pos + len(signature)
                else:
                    # For files without clear end signatures, take a reasonable chunk
                    file_data = data[pos:pos + min(self.max_carve_size, len(data) - pos)]
                    found_files.append((file_data, file_type))
                    start_pos = pos + len(signature)

        return found_files

    def get_extension_from_content_type(self, content_type: str) -> str:
        """Get file extension from content type"""
        content_type_map = {
            "image/jpeg": "jpg",
            "image/png": "png",
            "image/gif": "gif",
            "application/pdf": "pdf",
            "application/zip": "zip",
            "text/plain": "txt",
            "text/html": "html",
            "application/json": "json",
            "application/xml": "xml",
        }

        return content_type_map.get(content_type.lower(), "bin")

    def _unique_path(self, safe_name: str) -> str:
        """Return a path inside the output directory that will not clobber an earlier carve."""
        candidate = os.path.join(self.output_dir, safe_name)
        if not os.path.exists(candidate):
            return candidate
        root, dot, ext = safe_name.rpartition(".")
        stem, suffix = (root, "." + ext) if dot and root else (safe_name, "")
        counter = 1
        while True:
            candidate = os.path.join(self.output_dir, f"{stem}_{counter}{suffix}")
            if not os.path.exists(candidate):
                return candidate
            counter += 1

    def save_recovered_file(self, filename: str, data: bytes, source: str) -> None:
        """Save recovered file and log the recovery"""
        if len(self.recovered_files) >= self.max_files:
            if not self._max_files_warned:
                print(f"  [-] Recovery cap of {self.max_files} files reached; skipping further carves", file=sys.stderr)
                self._max_files_warned = True
            return

        safe_name = sanitize_filename(filename)
        if safe_name == RECOVERY_SUMMARY_NAME:
            # Keep carved data from being overwritten by the report below.
            safe_name = "carved_" + safe_name
        filepath = self._unique_path(safe_name)

        # Defence in depth: never write outside the output directory.
        output_root = os.path.realpath(self.output_dir)
        if os.path.commonpath([output_root, os.path.realpath(filepath)]) != output_root:
            print(f"  [-] Refusing to write outside output directory: {_printable(filename)!r}", file=sys.stderr)
            return

        try:
            with open(filepath, "wb") as f:
                f.write(data)
        except OSError as e:
            print(f"  [-] Error saving {safe_name}: {e}")
            return

        saved_name = os.path.basename(filepath)
        self.recovered_files.append({
            "filename": saved_name,
            "size": len(data),
            "source": source,
            "path": filepath,
        })

        print(f"  [+] Recovered: {saved_name} ({len(data)} bytes) from {source}")

    def generate_report(self) -> None:
        """Generate recovery report"""
        print("\n" + "=" * 60)
        print("FILE RECOVERY REPORT")
        print("=" * 60)

        if not self.recovered_files:
            print("No files were recovered from the network traffic.")
            return

        print(f"Total files recovered: {len(self.recovered_files)}")
        print(f"Files saved to: {self.output_dir}/")
        print("\nRecovered files:")
        print("-" * 60)

        for file_info in self.recovered_files:
            print(f"File: {file_info['filename']}")
            print(f"Size: {file_info['size']} bytes")
            print(f"Source: {file_info['source']}")
            print(f"Path: {file_info['path']}")
            print("-" * 40)

        # Generate summary file
        summary_path = os.path.join(self.output_dir, RECOVERY_SUMMARY_NAME)
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("FILE RECOVERY SUMMARY\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"PCAP File: {self.pcap_file}\n")
            f.write(f"Total Files Recovered: {len(self.recovered_files)}\n\n")

            for file_info in self.recovered_files:
                f.write(f"File: {file_info['filename']}\n")
                f.write(f"Size: {file_info['size']} bytes\n")
                f.write(f"Source: {file_info['source']}\n")
                f.write(f"Path: {file_info['path']}\n")
                f.write("-" * 40 + "\n")

        print(f"\nDetailed summary saved to: {summary_path}")
