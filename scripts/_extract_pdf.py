import sys, pathlib

src = sys.argv[1]
out = sys.argv[2]

try:
    import fitz  # PyMuPDF
except ImportError:
    print("PYMUPDF_MISSING")
    sys.exit(2)

doc = fitz.open(src)
parts = []
for i, page in enumerate(doc):
    parts.append(f"\n===== PAGE {i+1} =====\n")
    parts.append(page.get_text())

text = "".join(parts)
pathlib.Path(out).write_text(text, encoding="utf-8")
print(f"PAGES={len(doc)} CHARS={len(text)}")
print("WROTE", out)
