# IPA Architecture & Encryption Detector

A lightweight, fast, and standalone Python 3 script that scans `.ipa` (iOS App Store Package) files to detect Mach-O architectures and their encryption status without extracting the archive contents to disk.

## Features

- **No Extraction Required:** Reads files directly from the ZIP stream, making it exceptionally fast and saving disk I/O.
- **Zero Dependencies:** Built entirely using Python's standard library. No `pip install` required.
- **Universal (FAT) Binary Support:** Accurately parses FAT Mach-O headers to inspect every architecture slice independently.
- **Hidden Architecture Detection:** Automatically detects hidden ARM64 architectures that Apple's build tools intentionally omit from the FAT header count (rdar://15002326 compatibility workaround).
- **Encryption Detection:** Inspects `LC_ENCRYPTION_INFO` and `LC_ENCRYPTION_INFO_64` Mach-O load commands to determine if an architecture slice is FairPlay encrypted.
- **Metadata Extraction:** Parses the app's `Info.plist` to extract the Bundle ID, Display Name, Version, Build number, Minimum iOS Version, and Executable name.
- **Clean Output:** Generates a highly readable `ipa_report.txt` file summarizing all IPAs in the directory.
- **Cross-Platform:** Works out-of-the-box on macOS, Linux, and Windows.

## Requirements

- Python 3.8 or newer.

## Usage

1. Place `detect_arch.py` in a directory containing your `.ipa` files.
2. Open a terminal or command prompt in that directory.
3. Run the script:

   ```bash
   # Scan all .ipa files in the directory
   python detect_arch.py
   
   # Or specify particular .ipa files to scan
   python detect_arch.py App1.ipa App2.ipa
   ```

4. The script will process the `.ipa` files and generate a detailed `ipa_report.txt` file in the same directory.

## Example Output

```text
------------------------------------------------------
DragonStadium_1.10.3.ipa
------------------------------------------------------
Bundle ID:       es.socialpoint.dragonstadium
Display Name:    Dragon Stadium
Executable:      dragonstadium
Version:         1.10.3
Build:           1605131214
Minimum iOS:     7.0
Executable Size: 73.2 MB
Binary Type:     Universal

Architectures:
  armv7       : Encrypted
  arm64       : Encrypted [hidden slice]
```

## How It Works

1. **ZIP Streaming:** `.ipa` files are standard ZIP archives. The script uses Python's `zipfile` module to read bytes directly from the archive without extracting anything to disk.
2. **Metadata Parsing:** It locates `Payload/*.app/Info.plist` inside the ZIP and parses it using `plistlib`.
3. **Executable Discovery:** It uses the `CFBundleExecutable` value from the `Info.plist` to find the main Mach-O binary.
4. **Mach-O Parsing:**
   - It reads the first 4 bytes to check the Mach-O magic number.
   - If it's a Universal (FAT) binary, it parses the FAT header to find the offsets and sizes of each embedded architecture slice.
   - It accounts for Apple's `rdar://15002326` hack by scanning the padding between the FAT header and the first slice to identify any hidden ARM64 architectures omitted from the `nfat_arch` count.
   - It seeks to each slice's offset and reads the Mach-O header.
   - It iterates through the load commands looking for encryption info commands (`0x21` for 32-bit, `0x2C` for 64-bit).
   - If `cryptid` is `0`, the binary slice is decrypted; otherwise, it is encrypted.
