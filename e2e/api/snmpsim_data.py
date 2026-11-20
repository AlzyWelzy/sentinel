"""Prepares snmpsim data from netmon/testdata/walks: one <name>.snmpwalk per
recording (the community is the name), sorted by OID. The recordings were
taken subtree by subtree, and snmpsim answers GETNEXT wrongly from unsorted
data.

    python snmpsim_data.py OUT_DIR
    uvx --python 3.12 --from snmpsim-lextudio snmpsim-command-responder \\
        --data-dir=OUT_DIR --agent-udpv4-endpoint=127.0.0.1:1161 \\
        --agent-udpv4-endpoint=127.0.0.1:1162
"""

import sys
from pathlib import Path

WALKS = Path(__file__).resolve().parents[2] / "netmon" / "testdata" / "walks"


def records(text: str) -> list[str]:
    """One record per OID, on one line: a line not starting with an OID
    continues the last (a string with a newline in it), and snmpsim reads
    records a line each."""
    out: list[str] = []
    for line in text.splitlines():
        if line.startswith(".1.") or line.startswith("1."):
            out.append(line)
        elif out and line.strip(' "'):
            out[-1] += " " + line
        elif out:
            out[-1] += line.strip()
    return out


def key(record: str) -> tuple[int, ...]:
    oid = record.split(" ", 1)[0].lstrip(".")
    return tuple(int(p) for p in oid.split(".") if p.isdigit())


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for walk in sorted(WALKS.glob("*.walk")):
        recs = sorted(records(walk.read_text(errors="replace")), key=key)
        (out / f"{walk.stem}.snmpwalk").write_text("\n".join(recs) + "\n")
        print(walk.stem, len(recs))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
