import hashlib
import mimetypes
import os
import sys
import magic

def get_hashes(filepath):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()

def analyze_file(filepath):
    if not os.path.isfile(filepath):
        print(f"Error: File '{filepath}' not found.")
        return

    ext = os.path.splitext(filepath)[1].lower()

    # libmagic checks
    mime_detector = magic.Magic(mime=True)
    desc_detector = magic.Magic()

    detected_mime = mime_detector.from_file(filepath)
    detected_desc = desc_detector.from_file(filepath)

    # Map detected MIME type back to typical extensions
    expected_extensions = mimetypes.guess_all_extensions(detected_mime)

    md5_hash, sha256_hash = get_hashes(filepath)

    print(f"Target:        {os.path.abspath(filepath)}")
    print(f"Declared Ext:  {ext if ext else '(None)'}")
    print(f"MIME Type:     {detected_mime}")
    print(f"Description:   {detected_desc}")
    print(f"MD5:           {md5_hash}")
    print(f"SHA256:        {sha256_hash}")

    if expected_extensions and ext not in expected_extensions:
        print(f"ALERT: Extension mismatch. Expected one of: {expected_extensions}")
    else:
        print("Status: Extension appears consistent.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detect_magic.py <file>")
        sys.exit(1)
    analyze_file(sys.argv[1])