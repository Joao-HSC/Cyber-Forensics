import hashlib
import mimetypes
import os
import sys
import magic
import shutil

CHUNK_SIGNATURES = {
    b"IHDR": ("image/png", ".png", "PNG image with corrupted/tampered header"),
    b"%PDF-": ("application/pdf", ".pdf", "PDF document with corrupted/shifted header"),
    b"ftyp": ("video/mp4", ".mp4", "ISO Base Media / MP4 with non-zero offset"),
    b"ID3": ("audio/mpeg", ".mp3", "MP3 audio container"),
    b"PK\x03\x04": ("application/zip", ".zip", "ZIP/Office container with shifted header"),
    b"7z\xbc\xaf\x27\x1c": ("application/x-7z-compressed", ".7z", "7-Zip container"),
}

TRAILER_SIGNATURES = {
    b"IEND\xaeB`\x82": ("image/png", ".png", "PNG image (confirmed by IEND EOF chunk)"),
    b"%%EOF": ("application/pdf", ".pdf", "PDF document (confirmed by %%EOF trailer)"),
}

def get_hashes(filepath):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()

def deep_inspect_structure(filepath):
    """
    Scans the head and tail of the file for structural artifacts
    when the primary magic signature is corrupted or altered.
    """
    file_size = os.path.getsize(filepath)
    if file_size < 16:
        return None

    with open(filepath, "rb") as f:
        header = f.read(1024)
        
        # Check tail for standard EOF indicators
        seek_tail = max(0, file_size - 1024)
        f.seek(seek_tail)
        tail = f.read(1024)

    # 1. Check for PNG chunk anomaly (like IHDR at offset 12 with tampered magic bytes)
    if b"IHDR" in header[:64]:
        ihdr_idx = header.find(b"IHDR")
        if ihdr_idx in (12, 16):
            return {
                "mime": "image/png",
                "exts": [".png"],
                "desc": "PNG image (tampered magic bytes, valid IHDR chunk found)",
                "tampered": True,
                "fix_offset": 0,
                "fix_bytes": b"\x89PNG\r\n\x1a\n"
            }

    # 2. Check for trailer markers
    for marker, (mime, ext, desc) in TRAILER_SIGNATURES.items():
        if marker in tail:
            return {
                "mime": mime,
                "exts": [ext],
                "desc": f"{desc} (header missing or invalid)",
                "tampered": True,
                "fix_offset": None,
                "fix_bytes": None
            }

    # 3. Check for shifted or internal signatures within the first 1024 bytes
    for marker, (mime, ext, desc) in CHUNK_SIGNATURES.items():
        idx = header.find(marker)
        if idx > 0:
            return {
                "mime": mime,
                "exts": [ext],
                "desc": f"{desc} (found at offset 0x{idx:02X})",
                "tampered": True,
                "fix_offset": None,
                "fix_bytes": None
            }

    # 4. Check for embedded executables (PE/ELF) disguised with another header
    if header.startswith(b"MZ") and b"PE\x00\x00" in header:
        return {
            "mime": "application/x-dosexec",
            "exts": [".exe", ".dll", ".sys"],
            "desc": "Windows PE executable",
            "tampered": False,
            "fix_offset": None,
            "fix_bytes": None
        }

    return None

def analyze_file(filepath):
    if not os.path.isfile(filepath):
        print(f"Error: File '{filepath}' not found.")
        return

    ext = os.path.splitext(filepath)[1].lower()
    file_size = os.path.getsize(filepath)

    mime_detector = magic.Magic(mime=True)
    desc_detector = magic.Magic()

    detected_mime = mime_detector.from_file(filepath)
    detected_desc = desc_detector.from_file(filepath)

    is_tampered = False
    fix_data = None
    expected_extensions = []

    # If libmagic fails or defaults to raw data, run deep structural analysis
    if detected_mime == "application/octet-stream" or detected_desc == "data" or file_size < 128:
        structural_result = deep_inspect_structure(filepath)
        if structural_result:
            detected_mime = structural_result["mime"]
            detected_desc = structural_result["desc"]
            expected_extensions = structural_result["exts"]
            is_tampered = structural_result["tampered"]
            fix_data = structural_result
    else:
        expected_extensions = mimetypes.guess_all_extensions(detected_mime)

    # Common forensic MIME aliases
    overrides = {
        "text/plain": [".txt", ".log", ".cfg", ".conf", ".ini", ""],
        "application/x-executable": ["", ".bin"],
        "application/x-pie-executable": ["", ".bin"],
        "application/x-sharedlib": [".so", ""],
    }
    valid_exts = set(expected_extensions).union(overrides.get(detected_mime, []))

    md5_hash, sha256_hash = get_hashes(filepath)

    print(f"Target:        {os.path.abspath(filepath)}")
    print(f"Size:          {file_size} bytes")
    print(f"Declared Ext:  {ext if ext else '(None)'}")
    print(f"MIME Type:     {detected_mime}")
    print(f"Description:   {detected_desc}")
    print(f"MD5:           {md5_hash}")
    print(f"SHA256:        {sha256_hash}")

    if is_tampered:
        print("\n[CRITICAL FORENSIC ALERT]")
        print(" -> File header has been intentionally altered, disguised, or corrupted.")
        if fix_data and fix_data.get("fix_bytes") is not None:
            print(f" -> Remediation available: overwrite offset {fix_data['fix_offset']} with {fix_data['fix_bytes']!r}")
            print(f" -> Run with '--fix' flag to repair this artifact.")
    elif valid_exts and ext not in valid_exts:
        print(f"\nALERT: Extension mismatch. Expected one of: {sorted(list(valid_exts))}")
    else:
        print("\nStatus: Normal / Consistent.")

def repair_file(filepath):
    structural_result = deep_inspect_structure(filepath)
    if not structural_result or structural_result.get("fix_bytes") is None:
        print("Error: No automated fix pattern identified for this artifact.")
        return

    offset = structural_result["fix_offset"]
    fix_bytes = structural_result["fix_bytes"]
    target_ext = structural_result["exts"][0]

    # Generate a clean output path without modifying the original
    base, _ = os.path.splitext(filepath)
    output_path = f"{base}_recovered{target_ext}"

    # Duplicate evidence first, then patch the copy
    shutil.copy2(filepath, output_path)

    with open(output_path, "r+b") as f:
        f.seek(offset)
        f.write(fix_bytes)

    print(f"Original file left untouched: {filepath}")
    print(f"Forensic copy repaired ->    {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python file_type_detector.py [--fix] <file>")
        sys.exit(1)

    if sys.argv[1] == "--fix":
        if len(sys.argv) < 3:
            print("Specify file to fix: python file_type_detector.py --fix <file>")
            sys.exit(1)
        repair_file(sys.argv[2])
    else:
        analyze_file(sys.argv[1])