#!/usr/bin/env python3
import sys
import os
import codecs
from typing import Dict, Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

AES_KEY = bytes([
    0x06, 0x02, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00,
    0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00
])
AES_IV = bytes([
    0x01, 0x00, 0x01, 0x00, 0x67, 0x24, 0x4f, 0x43,
    0x6e, 0x67, 0x62, 0xf2, 0x5e, 0xa8, 0xd7, 0x04
])

ENC_FIELDS = [
    "SecurityPasswordAES",
    "OptionsPasswordAES",
    "ServerPasswordAES",
    "ProxyPasswordAES",
    "LicenseKeyAES",
    "SecurityPasswordExported"
]

# Important connection info fields to show
CONN_INFO_FIELDS = [
    "ClientID",
    "InstallationDate",
    "InstallationDirectory",
    "Version",
    "Always_Online",
    "StartMenuGroup",
    "LastUpdateCheck"
]

def parse_reg_file(filename: str) -> Dict[str, Dict[str, Union[str, int, bytes]]]:
    reg_data = {}
    current_key = None
    multiline = ""

    with open(filename, 'rb') as f:
        raw = f.read()
        encoding = 'utf-16' if raw.startswith(codecs.BOM_UTF16_LE) else 'utf-8'
        content = raw.decode(encoding, errors='ignore')

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        # Handle continuation lines ending with backslash
        if line.endswith("\\"):
            multiline += line[:-1]
            continue
        else:
            line = multiline + line
            multiline = ""

        if line.startswith('[') and line.endswith(']'):
            current_key = line[1:-1]
            reg_data[current_key] = {}
        elif '=' in line and current_key:
            try:
                name, value = line.split('=', 1)
                name = name.strip('"')
                reg_data[current_key][name] = parse_value(value)
            except Exception:
                pass
    return reg_data

def parse_value(value: str) -> Union[str, int, bytes]:
    value = value.strip()
    if value.startswith("hex:"):
        return bytes.fromhex(value[4:].replace(",", "").replace("\\", "").replace(" ", ""))
    elif value.startswith("hex(7):"):
        return bytes.fromhex(value[7:].replace(",", "").replace("\\", "").replace(" ", ""))
    elif value.startswith("dword:"):
        return int(value[6:], 16)
    else:
        return value.strip('"')

def decrypt_password(cipher_bytes: bytes) -> str:
    try:
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(cipher_bytes) + decryptor.finalize()
        # Remove trailing null bytes
        decrypted = padded.rstrip(b"\x00")
        return decrypted.decode('utf-8', errors='replace')
    except Exception:
        return "<decryption failed>"

def print_clean_info(data: Dict[str, Dict[str, Union[str, int, bytes]]]):
    print("\n========== TeamViewer Connection Info ==========\n")

    # Find the main TeamViewer key for Version7 or other versions
    main_key = None
    for key in data:
        if "TeamViewer" in key and ("Version7" in key or "Version" in key):
            main_key = key
            break
    if not main_key:
        print("[!] No TeamViewer main registry key found.")
        return

    info = data[main_key]

    # Print connection info
    for field in CONN_INFO_FIELDS:
        if field in info:
            val = info[field]
            if isinstance(val, bytes):
                # For bytes, just print length or hex summary
                print(f"{field:25}: (binary data, {len(val)} bytes)")
            else:
                print(f"{field:25}: {val}")

    # Print decrypted passwords (if any)
    print("\n========== Decrypted Passwords ==========\n")
    found_password = False
    for field in ENC_FIELDS:
        if field in info and isinstance(info[field], bytes):
            decrypted = decrypt_password(info[field])
            if decrypted and decrypted != "":
                found_password = True
                print(f"{field:25}: {decrypted}")

    if not found_password:
        print("[*] No encrypted passwords found or decryption failed.")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <teamviewer.reg>")
        sys.exit(1)

    reg_file = sys.argv[1]
    if not os.path.isfile(reg_file):
        print(f"[!] File not found: {reg_file}")
        sys.exit(1)

    data = parse_reg_file(reg_file)
    print_clean_info(data)

if __name__ == "__main__":
    main()
