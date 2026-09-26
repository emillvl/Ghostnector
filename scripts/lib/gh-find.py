#!/usr/bin/env python3
"""Find a word in a screenshot and print its centre as "X Y" for xdotool.

Usage: gh-find.py IMAGE WORD [--same-line-with OTHER] [--below WORD] [--above WORD]
                       [--min-y PIXELS] [--index N]

Exits 1 when nothing matches. Uses tesseract's TSV output (word-level boxes).
"""
import subprocess
import sys


def tsv(image):
    out = subprocess.run(
        ["tesseract", image, "stdout", "tsv"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    rows = []
    for line in out.splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 12:
            continue
        try:
            left, top, width, height = (int(fields[6]), int(fields[7]), int(fields[8]), int(fields[9]))
            conf = float(fields[10])
        except ValueError:
            continue
        text = fields[11].strip()
        if text:
            rows.append({"text": text, "left": left, "top": top, "width": width, "height": height, "conf": conf})
    return rows


def centre(row):
    return row["left"] + row["width"] // 2, row["top"] + row["height"] // 2


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    image, word = args[0], args[1]
    options = {}
    index = 0
    i = 2
    while i < len(args):
        key = args[i]
        if key == "--index":
            index = int(args[i + 1])
            i += 2
        elif key in ("--same-line-with", "--below", "--above", "--min-y"):
            options[key] = args[i + 1]
            i += 2
        else:
            print(f"unknown option {key}", file=sys.stderr)
            return 2

    rows = tsv(image)
    matches = [r for r in rows if r["text"].lower() == word.lower()]
    if "same-line-with" in options:
        other = options["same-line-with"].lower()
        anchors = [r for r in rows if r["text"].lower() == other]
        kept = []
        for match in matches:
            for anchor in anchors:
                if abs(match["top"] - anchor["top"]) <= 8:
                    kept.append(match)
                    break
        matches = kept
    if "below" in options:
        anchors = [r for r in rows if r["text"].lower() == options["below"].lower()]
        if anchors:
            limit = max(a["top"] + a["height"] for a in anchors)
            matches = [r for r in matches if r["top"] > limit]
    if "above" in options:
        anchors = [r for r in rows if r["text"].lower() == options["above"].lower()]
        if anchors:
            limit = min(a["top"] for a in anchors)
            matches = [r for r in matches if r["top"] < limit]
    if "min-y" in options:
        matches = [r for r in matches if r["top"] >= int(options["min-y"])]

    matches.sort(key=lambda r: (r["top"], r["left"]))
    if not matches:
        print(f"not found: {word}", file=sys.stderr)
        return 1
    chosen = matches[min(index, len(matches) - 1)]
    x, y = centre(chosen)
    print(f"{x} {y}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
