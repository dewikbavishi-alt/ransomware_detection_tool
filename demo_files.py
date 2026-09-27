"""Creates realistic sample files (text, CSV, Word, PNG, PDF) for demos and tests."""

import os
import random
import struct
import zipfile
import zlib

SANDBOX_MARKER = ".ransomware_sandbox"

WORDS = (
    "invoice client project report budget meeting quarterly revenue team schedule "
    "delivery review contract payment summary update proposal target customer "
    "analysis design release sprint feedback approval account order supplier"
).split()


def sentence(rng):
    words = rng.choices(WORDS, k=rng.randint(6, 14))
    return " ".join(words).capitalize() + "."


def paragraph(rng, sentences):
    return " ".join(sentence(rng) for _ in range(sentences))


def make_docx(path, text):
    """A minimal Word document: a zip file holding the document XML."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as docx:
        docx.writestr("[Content_Types].xml",
                      '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        docx.writestr("word/document.xml",
                      f'<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>')


def make_png(rng, width=48, height=48):
    rows = b"".join(
        b"\x00" + bytes(rng.randrange(256) for _ in range(width * 3)) for _ in range(height))

    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def make_pdf(text):
    stream = f"BT /F1 11 Tf 72 720 Td ({text}) Tj ET"
    return (
        "%PDF-1.4\n"
        "1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n"
        "2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj\n"
        "3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        "/Resources <</Font <</F1 5 0 R>>>>>> endobj\n"
        f"4 0 obj <</Length {len(stream)}>> stream\n{stream}\nendstream endobj\n"
        "5 0 obj <</Type /Font /Subtype /Type1 /BaseFont /Helvetica>> endobj\n"
        "trailer <</Root 1 0 R>>\n%%EOF\n"
    ).encode("latin-1")


def create_demo_files(folder, sets=4, seed=7):
    """Create sets x 6 sample files and mark the folder as a sandbox."""
    rng = random.Random(seed)
    os.makedirs(folder, exist_ok=True)

    with open(os.path.join(folder, SANDBOX_MARKER), "w", encoding="utf-8") as marker:
        marker.write("Test folder: the attack simulator is allowed to run here.\n")

    created = []

    def write(name, data):
        path = os.path.join(folder, name)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(path, mode, **({} if mode == "wb" else {"encoding": "utf-8"})) as file:
            file.write(data)
        created.append(path)

    for i in range(1, sets + 1):
        write(f"meeting_notes_{i}.txt", "\n\n".join(paragraph(rng, 5) for _ in range(rng.randint(3, 8))))
        write(f"sales_q{i}.csv", "date,client,amount\n" + "\n".join(
            f"2026-0{rng.randint(1, 9)}-{rng.randint(10, 28)},{rng.choice(WORDS)},{rng.randint(500, 90000)}"
            for _ in range(rng.randint(40, 120))))
        write(f"project_plan_{i}.md", f"# Project {i}\n\n" + "\n\n".join(paragraph(rng, 4) for _ in range(4)))
        make_docx(os.path.join(folder, f"contract_{i}.docx"), paragraph(rng, 30))
        created.append(os.path.join(folder, f"contract_{i}.docx"))
        write(f"photo_{i}.png", make_png(rng))
        write(f"invoice_{i}.pdf", make_pdf(paragraph(rng, 3)))

    return created


if __name__ == "__main__":
    import config

    files = create_demo_files(config.WATCH_FOLDER)
    print(f"Created {len(files)} sample files in {config.WATCH_FOLDER}")
