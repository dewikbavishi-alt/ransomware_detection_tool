"""Checks that a file's content still matches its type."""

import codecs

# The first bytes ("magic number") every valid file of this type starts with
MAGIC_NUMBERS = {
    ".pdf": [b"%PDF"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".bmp": [b"BM"],
    ".zip": [b"PK\x03\x04", b"PK\x05\x06"],
    ".docx": [b"PK\x03\x04"],
    ".xlsx": [b"PK\x03\x04"],
    ".pptx": [b"PK\x03\x04"],
    ".doc": [b"\xd0\xcf\x11\xe0"],
    ".xls": [b"\xd0\xcf\x11\xe0"],
    ".ppt": [b"\xd0\xcf\x11\xe0"],
    ".7z": [b"7z\xbc\xaf\x27\x1c"],
    ".gz": [b"\x1f\x8b"],
    ".rar": [b"Rar!\x1a\x07"],
    ".exe": [b"MZ"],
    ".dll": [b"MZ"],
}

TEXT_EXTENSIONS = {
    ".txt", ".csv", ".md", ".json", ".xml", ".html", ".htm", ".css", ".js",
    ".py", ".java", ".c", ".cpp", ".h", ".log", ".ini", ".yml", ".yaml", ".sql",
}

# Formats that are compressed by design, so high entropy is normal for them
COMPRESSED_EXTENSIONS = {
    ".zip", ".7z", ".rar", ".gz", ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".mp3", ".mp4", ".mkv", ".pdf", ".docx", ".xlsx", ".pptx",
}

TEXT_BOMS = [codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE]


def header_matches(extension, data):
    """True or False for known types, None when the type has no known header."""
    signatures = MAGIC_NUMBERS.get(extension)
    if signatures is None or not data:
        return None
    return any(data.startswith(signature) for signature in signatures)


def looks_like_text(data):
    if not data or any(data.startswith(bom) for bom in TEXT_BOMS):
        return True

    # final=False tolerates a character cut in half at the end of the sample
    try:
        codecs.getincrementaldecoder("utf-8")().decode(data, final=False)
        return True
    except UnicodeDecodeError:
        pass

    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(data) > 0.85
