# TeamViewer Registry Extractor

A Python script to extract and decrypt important TeamViewer connection information from Windows registry export files (`.reg`), including the TeamViewer client ID, installation details, version, and decrypted TeamViewer passwords.

---

## Features

- Parses TeamViewer registry `.reg` files exported from Windows machines.
- Extracts key connection information like ClientID, InstallationDate, Version, and more.
- Decrypts AES-encrypted TeamViewer passwords stored in the registry.
- Outputs clean, easy-to-read information useful for red team, forensic, or recovery tasks.
- Supports TeamViewer Version 7 and similar versions.

---

## Requirements

- Python 3.6+
- [cryptography](https://cryptography.io/en/latest/) Python package

Install dependencies with:

```bash
pip install cryptography
````

---

## Usage

Export the TeamViewer registry keys from the target machine (usually from the path):

```
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\TeamViewer\Version7
```

Save it as a `.reg` file, then run:

```bash
python extract_teamviewer_info_clean.py <path_to_exported_reg_file>
```

Example:

```bash
python extract_teamviewer_info_clean.py teamviewer_export.reg
```

---

## Output

The script prints:

* TeamViewer client connection information (ClientID, InstallationDate, Version, etc.)
* Decrypted TeamViewer passwords (if available)

Example output:

```
========== TeamViewer Connection Info ==========

ClientID                : 702121069
InstallationDate        : 2020-12-16
InstallationDirectory   : C:\Program Files (x86)\TeamViewer\Version7
Version                 : 7.0.43148
Always_Online           : 0
StartMenuGroup          : TeamViewer 7
LastUpdateCheck         : 1608134117

========== Decrypted Passwords ==========

SecurityPasswordAES     : your_decrypted_password_here
```

---

## Disclaimer

This tool is intended for legitimate security assessments, forensic analysis, or personal recovery purposes only. Unauthorized use on systems you do not own or have explicit permission to test is illegal and unethical.

Use responsibly.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contributions

Contributions, issues, and feature requests are welcome! Feel free to fork the repo and submit pull requests.

---

## Author

Created by Mohammad Agha Sulaiman Zai
