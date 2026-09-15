import argparse
import mimetypes
import os
import shutil
import magic

# Fallback carving rules: only applied if libmagic fails to identify the format
CARVE_RULES = [
    {
        "marker": b"IHDR",
        "max_offset": 64,
        "mime": "image/png",
        "ext": ".png",
        "issue": "Corrupted PNG header (valid IHDR chunk located)",
        "patch": (0, b"\x89PNG\r\n\x1a\n"),
    },
    {
        "marker": b"%%EOF",
        "tail_search": True,
        "mime": "application/pdf",
        "ext": ".pdf",
        "issue": "PDF trailer found but header missing/corrupted",
        "patch": None,
    },
    {
        "marker": b"ftyp",
        "max_offset": 32,
        "mime": "video/mp4",
        "ext": ".mp4",
        "issue": "MP4 container with offset header",
        "patch": None,
    },
]

COMMON_EXT_MAP = {
    "text/plain": {".txt", ".log", ".cfg", ".conf", ".ini", ".url", ".srt", ""},
    "application/x-executable": {"", ".bin"},
    "application/x-pie-executable": {"", ".bin"},
    "application/x-sharedlib": {".so", ""},
    "application/json": {".json", ".parts.json"},
    "application/x-dosexec": {".exe", ".dll", ".sys"},
}

def carve_corrupted_file(filepath):
    """Deep check executed ONLY when libmagic yields raw data/octet-stream."""
    size = os.path.getsize(filepath)
    if size < 16:
        return None

    with open(filepath, "rb") as f:
        head = f.read(2048)
        seek_tail = max(0, size - 2048)
        f.seek(seek_tail)
        tail = f.read(2048)

    for rule in CARVE_RULES:
        if rule.get("tail_search"):
            if rule["marker"] in tail:
                return rule
        else:
            idx = head.find(rule["marker"])
            if idx != -1 and idx <= rule.get("max_offset", 1024):
                return rule
    return None

def recover_evidence(filepath, target_ext, patch=None):
    base, _ = os.path.splitext(filepath)
    out_path = f"{base}_recovered{target_ext}"
    shutil.copy2(filepath, out_path)

    if patch:
        offset, patch_bytes = patch
        with open(out_path, "r+b") as f:
            f.seek(offset)
            f.write(patch_bytes)
    return os.path.basename(out_path)

def inspect_directory(target_path, do_fix=False):
    mime_engine = magic.Magic(mime=True)
    files_to_check = []

    if os.path.isfile(target_path):
        files_to_check = [target_path]
    else:
        for root, _, files in os.walk(target_path):
            for f in sorted(files):
                if "_recovered" not in f:
                    files_to_check.append(os.path.join(root, f))

    header = f"{'FILENAME':<35} {'DECLARED':<10} {'ACTUAL':<10} {'ISSUE':<40} {'RECOVERED' if do_fix else ''}"
    print("\n" + header)
    print("-" * (len(header) + 15))

    for path in files_to_check:
        if os.path.getsize(path) == 0:
            continue

        ext = os.path.splitext(path)[1].lower()
        try:
            detected_mime = mime_engine.from_file(path)
        except Exception:
            continue

        issue = None
        target_ext = ""
        patch = None

        # Scenario 1: libmagic recognized the structure cleanly
        if detected_mime not in ("application/octet-stream", "data"):
            known_exts = set(mimetypes.guess_all_extensions(detected_mime)).union(
                COMMON_EXT_MAP.get(detected_mime, set())
            )
            target_ext = mimetypes.guess_extension(detected_mime) or ""

            # Check for pure extension disguise (e.g. .mp4 named as .txt)
            if known_exts and ext not in known_exts:
                issue = f"Extension mismatch ({detected_mime})"

        # Scenario 2: libmagic could not recognize it -> Header tampered or raw binary
        else:
            carved = carve_corrupted_file(path)
            if carved:
                issue = carved["issue"]
                target_ext = carved["ext"]
                patch = carved["patch"]

        if not issue:
            continue

        recovered_str = ""
        if do_fix:
            out_ext = target_ext if target_ext else ".bin"
            recovered_str = recover_evidence(path, out_ext, patch)

        fname = os.path.basename(path)
        if len(fname) > 33:
            fname = fname[:30] + "..."

        print(f"{fname:<35} {ext if ext else '(none)':<10} {target_ext:<10} {issue:<40} {recovered_str}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="File or folder to audit")
    parser.add_argument("--fix", action="store_true", help="Carve and generate recovered copies")
    args = parser.parse_args()

    inspect_directory(args.target, do_fix=args.fix)