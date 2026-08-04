import os
import glob
import zipfile
import plistlib
import struct
import re
import argparse

def natural_sort_key(s):
    return [int(text) if text.isdigit() else text.lower() for text in re.split('([0-9]+)', s)]

def format_size(size_in_bytes):
    return f"{size_in_bytes / (1024 * 1024):.1f} MB"

def get_arch_name(cputype, cpusubtype):
    cpusubtype = cpusubtype & 0x00FFFFFF
    if cputype == 12:
        if cpusubtype == 6: return "armv6"
        if cpusubtype == 9: return "armv7"
        if cpusubtype == 11: return "armv7s"
        return f"arm_unknown_{cpusubtype}"
    elif cputype == 16777228:
        if cpusubtype == 0 or cpusubtype == 1: return "arm64"
        if cpusubtype == 2: return "arm64e"
        return f"arm64_unknown_{cpusubtype}"
    elif cputype == 7:
        return "x86"
    elif cputype == 16777223:
        return "x86_64"
    return f"unknown_{cputype}_{cpusubtype}"

def parse_macho(ef, offset, current_pos):
    if offset > current_pos:
        skip = offset - current_pos
        while skip > 0:
            chunk = min(skip, 1024 * 1024)
            data = ef.read(chunk)
            if not data:
                break
            skip -= len(data)
        current_pos = offset
        
    header = ef.read(32)
    current_pos += len(header)
    if len(header) < 28:
        return {"error": "Invalid Mach-O header"}, current_pos
        
    magic_bytes = header[:4]
    magic = struct.unpack(">I", magic_bytes)[0]
    
    is_64 = False
    if magic == 0xfeedface:
        endian = ">"
    elif magic == 0xcefaedfe:
        endian = "<"
    elif magic == 0xfeedfacf:
        endian = ">"
        is_64 = True
    elif magic == 0xcffaedfe:
        endian = "<"
        is_64 = True
    else:
        return {"error": f"Unknown Mach-O magic {hex(magic)}"}, current_pos
        
    if is_64:
        if len(header) < 32:
            return {"error": "Invalid Mach-O 64-bit header"}, current_pos
        magic_val, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(f"{endian}IiiIIIII", header[:32])
        if sizeofcmds > 10 * 1024 * 1024:
            return {"error": "sizeofcmds too large"}, current_pos
            
        cmds_data = b""
        while len(cmds_data) < sizeofcmds:
            chunk = ef.read(sizeofcmds - len(cmds_data))
            if not chunk: break
            cmds_data += chunk
        current_pos += len(cmds_data)
    else:
        magic_val, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(f"{endian}IiiIIII", header[:28])
        if sizeofcmds > 10 * 1024 * 1024:
            return {"error": "sizeofcmds too large"}, current_pos
            
        if sizeofcmds < 4:
            cmds_data = b""
        else:
            to_read = sizeofcmds - 4
            cmds_data = header[28:32]
            while len(cmds_data) < sizeofcmds:
                chunk = ef.read(sizeofcmds - len(cmds_data))
                if not chunk: break
                cmds_data += chunk
            current_pos += to_read
            
    arch_name = get_arch_name(cputype, cpusubtype)
    encrypted = False
    
    cmd_pos = 0
    for _ in range(ncmds):
        if cmd_pos + 8 > len(cmds_data):
            break
        cmd, cmdsize = struct.unpack(f"{endian}II", cmds_data[cmd_pos:cmd_pos+8])
        
        if cmd == 0x21:
            if cmd_pos + 20 <= len(cmds_data):
                cryptoff, cryptsize, cryptid = struct.unpack(f"{endian}III", cmds_data[cmd_pos+8:cmd_pos+20])
                if cryptid != 0:
                    encrypted = True
        elif cmd == 0x2C:
            if cmd_pos + 24 <= len(cmds_data):
                cryptoff, cryptsize, cryptid, pad = struct.unpack(f"{endian}IIII", cmds_data[cmd_pos+8:cmd_pos+24])
                if cryptid != 0:
                    encrypted = True
                    
        if cmdsize == 0:
            break
        cmd_pos += cmdsize
        
    return {
        "arch": arch_name,
        "encrypted": encrypted
    }, current_pos

def process_ipa(ipa_path):
    result = {
        "filename": os.path.basename(ipa_path),
        "error": None
    }
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            app_dir = None
            for name in zf.namelist():
                if name.startswith("Payload/") and ".app" in name:
                    parts = name.split("/")
                    if len(parts) >= 2 and parts[1].endswith(".app"):
                        app_dir = f"Payload/{parts[1]}/"
                        break
                        
            if not app_dir:
                result["error"] = "Could not find Payload/*.app/ directory"
                return result
                
            info_plist_path = f"{app_dir}Info.plist"
            try:
                with zf.open(info_plist_path) as pf:
                    plist_data = pf.read()
                    try:
                        plist = plistlib.loads(plist_data)
                    except Exception:
                        plist = plistlib.loads(plist_data, fmt=None)
            except KeyError:
                result["error"] = f"Could not find {info_plist_path}"
                return result
            except Exception as e:
                result["error"] = f"Failed to parse Info.plist: {str(e)}"
                return result
                
            result["bundle_id"] = plist.get("CFBundleIdentifier", "Unknown")
            result["version"] = plist.get("CFBundleShortVersionString", "Unknown")
            result["build"] = plist.get("CFBundleVersion", "Unknown")
            result["executable_name"] = plist.get("CFBundleExecutable", "Unknown")
            result["min_os"] = plist.get("MinimumOSVersion", "Unknown")
            result["display_name"] = plist.get("CFBundleDisplayName", "Unknown")
            
            if result["executable_name"] == "Unknown":
                result["error"] = "Info.plist does not contain CFBundleExecutable"
                return result
                
            exec_path = f"{app_dir}{result['executable_name']}"
            try:
                exec_info = zf.getinfo(exec_path)
            except KeyError:
                result["error"] = f"Executable {exec_path} not found in archive"
                return result
                
            result["executable_size"] = exec_info.file_size
            
            with zf.open(exec_path) as ef:
                magic_bytes = ef.read(4)
                if len(magic_bytes) < 4:
                    result["error"] = "Executable file is too small"
                    return result
                magic = struct.unpack(">I", magic_bytes)[0]
                is_fat = magic in (0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca)
                
            if is_fat:
                with zf.open(exec_path) as ef:
                    magic_bytes = ef.read(4)
                    current_pos = 4
                    magic = struct.unpack(">I", magic_bytes)[0]
                    
                    if magic == 0xcafebabe:
                        endian = ">"
                        is_fat64 = False
                    elif magic == 0xbebafeca:
                        endian = "<"
                        is_fat64 = False
                    elif magic == 0xcafebabf:
                        endian = ">"
                        is_fat64 = True
                    else:
                        endian = "<"
                        is_fat64 = True
                        
                    result["binary_type"] = "Universal"
                    nfat_bytes = ef.read(4)
                    current_pos += 4
                    nfat_arch = struct.unpack(f"{endian}I", nfat_bytes)[0]
                    
                    archs = []
                    first_offset = 0xFFFFFFFF
                    
                    for i in range(nfat_arch):
                        if is_fat64:
                            arch_data = ef.read(32)
                            current_pos += 32
                            cputype, cpusubtype, offset, size, align, reserved = struct.unpack(f"{endian}iiQQII", arch_data)
                        else:
                            arch_data = ef.read(20)
                            current_pos += 20
                            cputype, cpusubtype, offset, size, align = struct.unpack(f"{endian}iiIII", arch_data)
                        
                        if offset < first_offset:
                            first_offset = offset
                            
                        archs.append((offset, size, i, False))
                        
                    entry_size = 32 if is_fat64 else 20
                    hidden_index = nfat_arch
                    while current_pos + entry_size <= first_offset:
                        arch_data = ef.read(entry_size)
                        if len(arch_data) < entry_size:
                            break
                        
                        if is_fat64:
                            cputype, cpusubtype, offset, size, align, reserved = struct.unpack(f"{endian}iiQQII", arch_data)
                        else:
                            cputype, cpusubtype, offset, size, align = struct.unpack(f"{endian}iiIII", arch_data)
                            
                        if cputype == 16777228:
                            archs.append((offset, size, hidden_index, True))
                            hidden_index += 1
                            current_pos += entry_size
                        else:
                            current_pos += entry_size
                            break
                            
                    archs_sorted = sorted(archs, key=lambda x: x[0])
                    
                    results = [None] * len(archs)
                    for offset, size, index, is_hidden in archs_sorted:
                        arch_info, current_pos = parse_macho(ef, offset, current_pos)
                        if "error" in arch_info:
                            result["error"] = arch_info["error"]
                            return result
                        
                        arch_info["is_hidden"] = is_hidden
                            
                        results[index] = arch_info
                        
                    result["architectures"] = results
            else:
                with zf.open(exec_path) as ef:
                    result["binary_type"] = "Thin"
                    arch_info, _ = parse_macho(ef, 0, 0)
                    if "error" in arch_info:
                        result["error"] = arch_info["error"]
                        return result
                    result["architectures"] = [arch_info]
                    
    except zipfile.BadZipFile:
        result["error"] = "Not a valid ZIP/IPA file"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        
    return result

def main():
    parser = argparse.ArgumentParser(description="Scan IPA files for architectures and encryption status.")
    parser.add_argument("files", nargs="*", help="Specific .ipa files to scan. If none provided, scans all .ipa files in the current directory.")
    args = parser.parse_args()
    
    if args.files:
        ipa_files = args.files
    else:
        ipa_files = glob.glob("*.ipa")
        if not ipa_files:
            # Fallback to script directory in case of double-click
            script_dir = os.path.dirname(os.path.abspath(__file__))
            if script_dir and os.path.abspath(os.getcwd()) != script_dir:
                os.chdir(script_dir)
                ipa_files = glob.glob("*.ipa")
        
    if not ipa_files:
        print("No .ipa files found in the current directory or script directory.")
        return
        
    ipa_files.sort(key=natural_sort_key)
        
    lines = []
    
    for i, ipa in enumerate(ipa_files):
        print(f"Processing {ipa}...")
        
        if i > 0:
            lines.append("")
            
        lines.append("-" * 54)
        lines.append(f"{ipa}")
        lines.append("-" * 54)
        
        res = process_ipa(ipa)
        
        if res.get("error"):
            lines.append(f"ERROR: {res['error']}")
            continue
            
        lines.append(f"Bundle ID:       {res['bundle_id']}")
        if res['display_name'] != "Unknown":
            lines.append(f"Display Name:    {res['display_name']}")
        lines.append(f"Executable:      {res['executable_name']}")
        lines.append(f"Version:         {res['version']}")
        lines.append(f"Build:           {res['build']}")
        lines.append(f"Minimum iOS:     {res['min_os']}")
        lines.append(f"Executable Size: {format_size(res['executable_size'])}")
        lines.append(f"Binary Type:     {res['binary_type']}")
        lines.append("")
        
        if res['binary_type'] == "Universal":
            lines.append("Architectures:")
        else:
            lines.append("Architecture:")
            
        for arch in res['architectures']:
            enc_status = "Encrypted" if arch['encrypted'] else "Decrypted"
            if arch.get('is_hidden'):
                lines.append(f"  {arch['arch']:<11} : {enc_status} [hidden slice]")
            else:
                lines.append(f"  {arch['arch']:<11} : {enc_status}")
            
    with open("ipa_report.txt", "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")
                
    print("Report generated: ipa_report.txt")

if __name__ == "__main__":
    main()
    input("\nPress Enter to exit...")
