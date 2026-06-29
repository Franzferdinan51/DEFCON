import base64, pathlib, sys
TARGET = pathlib.Path(r"C:\Users\franz\Projects\DEFCON\scripts")

CHUNKS = {
    "attacker_intel.py": [
        "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uIwoiIyMgREVGQ09OIEF0dGFja2VyIEludGVsbGlnZW5jZSBWMy40IC0gQ29sbGVj",
        "dCBBdHRhY2tlciBJUCwgR2VvLUlQLCBTaG9kYW4sIFZpcnVzVG90YWwgUG9ydGFsIERhdGFiYXNlIChGcmVl",
        "dGllciBMaW1pdCkKIyMgVWdzZTogUHl0aG9uIGRlZmNvbl9hdHRhY2tlcl9pbnRlbC5weSB8",
        "fCBweXRoeCAtLXFsdWljayB8IC1tcSBmaWxlIChkZWZhdWx0KQojIwoj",
        "IE11c3QgcnVuIGFmdGVyOiBoYWNrX3Jlc3BvbnNlLnB5IC0tY29sbGVjdAo=",
    ],
    "forensics.py": [
        "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uIwoiIyMgREVGQ09OIEZvcmVuc2ljcyAtIERpZ2l0YWwgRm9y",
        "ZW5zaWNzIFN1aXRlIHYzLjQgLSBXaW5kb3dzICsgTGludXggKyBXaXJlc2hhcmtrIFBDQVAgKFBh",
        "cnNlc1dpdGhvdXRBZGRyZXNzKQo=",
    ],
}

for fname, b64_chunks in CHUNKS.items():
    decoded = b"".join(base64.b64decode(c) for c in b64_chunks).decode("utf-8")
    out = TARGET / fname
    out.write_text(decoded, encoding="utf-8")
    print(f"Wrote: {fname} ({len(decoded)} chars)")
print("Done")
