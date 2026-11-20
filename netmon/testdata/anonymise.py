"""Anonymises SNMP recordings (snmpwalk -On output) before they're committed.

    python anonymise.py walks/*.walk          # rewrites the files in place

Run it over every new recording. It keeps what the profiles and tests need
(OIDs, table structure, counters, interface names, vendor, model and version
strings) and replaces what identifies a network or its owner:

- names and free text: sysName, sysLocation, sysContact, interface aliases,
  LLDP neighbour names and port descriptions, entity aliases and asset ids,
  and any enterprise string that isn't a version or model code;
- serial numbers and server UUIDs (same shape, made-up digits);
- IPv4 addresses, in values, in hex and inside OID indexes;
- MAC addresses (vendor prefix kept), in values and inside OID indexes.

The mapping is deterministic and shared by all files given in one run, so an
LLDP neighbour named in one recording still matches the device in another.
Check the result by eye: `grep -h STRING walks/*.walk | sort -u | less`.
"""

import hashlib
import ipaddress
import re
import sys
from pathlib import Path

SECRET = b"sentinel-walks"

# Words that identify the network's owner wherever they appear.
TOKENS = [
]

# Columns whose text is free-form and always replaced (prefixes, no index).
FREE_TEXT = [
    ".1.3.6.1.2.1.1.4.0",  # sysContact
    ".1.3.6.1.2.1.1.5.0",  # sysName
    ".1.3.6.1.2.1.1.6.0",  # sysLocation
    ".1.3.6.1.2.1.31.1.1.1.18.",  # ifAlias
    ".1.3.6.1.2.1.47.1.1.1.1.14.",  # entPhysicalAlias
    ".1.3.6.1.2.1.47.1.1.1.1.15.",  # entPhysicalAssetID
    ".1.0.8802.1.1.2.1.3.3.0",  # lldpLocSysName
    ".1.0.8802.1.1.2.1.3.7.1.4.",  # lldpLocPortDesc
    ".1.0.8802.1.1.2.1.4.1.1.8.",  # lldpRemPortDesc
    ".1.0.8802.1.1.2.1.4.1.1.9.",  # lldpRemSysName
]
SERIAL = [
    ".1.3.6.1.2.1.47.1.1.1.1.11.",  # entPhysicalSerialNum
    ".1.3.6.1.4.1.12356.100.1.1.1.0",  # FortiGate fnSysSerial
    ".1.3.6.1.4.1.12356.101.13.2.1.1.2.",  # FortiGate HA member serial
    ".1.3.6.1.4.1.12356.101.13.2.1.1.16.",  # FortiGate HA master serial
    ".1.3.6.1.4.1.2604.5.1.1.4.0",  # Sophos appliance serial
    ".1.3.6.1.4.1.2604.5.1.4.2.0",  # Sophos appliance key
]

LINE = re.compile(r"^(\.[\d.]+) = ([A-Za-z0-9-]+): ?(.*)$")
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
MAC_TEXT = re.compile(r"(?i)\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b")
UUID = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)
VERSIONISH = re.compile(r"^v?\d[\w.,()+ -]{0,40}$")
MODELISH = re.compile(r"^[A-Z0-9][A-Z0-9_./+-]{1,30}$")
IFNAMEISH = re.compile(
    r"(?i)^(ethernet|eth|port-?channel|po|vlan|management|mgmt|loopback|lo|ge|xe|te|gi|fa|"
    r"trk|tunnel|port|lag|wan|lan|dmz|ha|internal|ssl\.|npu|x\d|mlag)[\w./ -]*$|^\d+(/\d+)*$"
)


def digest(*parts: str) -> bytes:
    return hashlib.sha256(SECRET + "\0".join(parts).encode()).digest()


class Mapper:
    def __init__(self) -> None:
        self.ips: dict[str, str] = {}
        self.macs: dict[str, str] = {}  # "aabbccddeeff" -> same form
        self.names: dict[str, str] = {}
        self.serials: dict[str, str] = {}
        self.known_ips: set[str] = set()  # only these are remapped inside text

    # --- addresses ---------------------------------------------------------
    def ip(self, value: str) -> str:
        if value in self.ips:
            return self.ips[value]
        try:
            a = ipaddress.IPv4Address(value)
        except ValueError:
            return value
        if (
            a.is_loopback
            or a.is_unspecified
            or a.is_multicast
            or a.is_link_local
            or str(a).startswith("255.")
        ):
            return value
        if str(a).endswith(".0") and value.count(".") == 3 and value.startswith("0."):
            return value
        h = digest("ip", value)
        if a.is_private:
            new = f"10.{h[0] % 200 + 20}.{h[1]}.{h[2] % 253 + 1}"
        else:
            # Documentation ranges: 198.51.100.0/24 and 203.0.113.0/24.
            new = f"{'198.51.100' if h[0] % 2 else '203.0.113'}.{h[1] % 253 + 1}"
        self.ips[value] = new
        return new

    def mac(self, raw: bytes) -> bytes:
        key = raw.hex()
        if key not in self.macs:
            if raw in (b"\x00" * 6, b"\xff" * 6):
                self.macs[key] = key
            else:
                h = digest("mac", key)
                self.macs[key] = (raw[:3] + h[:3]).hex()
        return bytes.fromhex(self.macs[key])

    # --- text --------------------------------------------------------------
    def name(self, value: str, kind: str = "name") -> str:
        bare = value.strip().strip('"')
        if not bare or IFNAMEISH.match(bare) and not self.sensitive(bare):
            return value
        if bare not in self.names:
            self.names[bare] = f"{kind}-{digest(kind, bare).hex()[:6]}"
        return value.replace(bare, self.names[bare])

    def serial(self, value: str) -> str:
        bare = value.strip().strip('"')
        if not bare:
            return value
        if bare not in self.serials:
            h = digest("serial", bare).hex()
            letters = re.match(r"^[A-Za-z]*", bare).group(0)
            digits = "".join(str(int(c, 16) % 10) for c in h)
            self.serials[bare] = (letters + digits)[: len(bare)]
        return value.replace(bare, self.serials[bare])

    @staticmethod
    def sensitive(text: str) -> bool:
        low = text.lower()
        return any(re.search(rf"(?<![a-z]){t}", low) for t in TOKENS)

    def text(self, value: str) -> str:
        """Any string: addresses and UUIDs remapped, owner words replaced."""
        value = IPV4.sub(
            lambda m: (
                self.ip(m.group(1)) if m.group(1) in self.known_ips else m.group(1)
            ),
            value,
        )
        value = MAC_TEXT.sub(
            lambda m: ":".join(
                f"{b:02x}"
                for b in self.mac(bytes.fromhex(re.sub("[:-]", "", m.group(1))))
            ),
            value,
        )
        value = UUID.sub(
            lambda m: str(
                __import__("uuid").UUID(bytes=digest("uuid", m.group(0).lower())[:16])
            ),
            value,
        )
        for old, new in self.serials.items():
            if len(old) >= 6 and old in value:
                value = value.replace(old, new)
        if self.sensitive(value):
            value = self.name(value)
        return value


def known_ips(lines: list[str]) -> set[str]:
    out = set()
    for line in lines:
        m = LINE.match(line)
        if m and m.group(2) == "IpAddress":
            out.add(m.group(3).strip())
    return out


def known_macs(lines: list[str]) -> set[str]:
    out = set()
    for line in lines:
        m = LINE.match(line)
        if m and m.group(2) == "Hex-STRING":
            raw = bytes.fromhex(m.group(3).replace(" ", ""))
            if len(raw) == 6:
                out.add(raw.hex())
    return out


def remap_oid(oid: str, mp: Mapper, ips: set[str], macs: set[str]) -> str:
    parts = oid.lstrip(".").split(".")
    # IPs inside indexes: any 4 consecutive arcs that spell a known address.
    i = 0
    while i + 4 <= len(parts):
        cand = ".".join(parts[i : i + 4])
        if cand in ips:
            parts[i : i + 4] = mp.ip(cand).split(".")
            i += 4
            continue
        i += 1
    i = 0
    while i + 6 <= len(parts):
        try:
            raw = bytes(int(p) for p in parts[i : i + 6])
        except ValueError:
            i += 1
            continue
        if raw.hex() in macs:
            parts[i : i + 6] = [str(b) for b in mp.mac(raw)]
            i += 6
            continue
        i += 1
    return "." + ".".join(parts)


def anonymise(lines: list[str], mp: Mapper, ips: set[str], macs: set[str]) -> list[str]:
    out = []
    for line in lines:
        m = LINE.match(line)
        if not m:
            out.append(mp.text(line))  # continuation of a multi-line string
            continue
        oid, typ, val = m.groups()
        oid = remap_oid(oid, mp, ips, macs)
        if typ == "IpAddress":
            val = mp.ip(val.strip())
        elif typ == "Hex-STRING":
            raw = bytes.fromhex(val.replace(" ", ""))
            if len(raw) == 6 and raw.hex() in macs:
                raw = mp.mac(raw)
            elif len(raw) == 4 and ".".join(str(b) for b in raw) in ips:
                raw = bytes(
                    int(p) for p in mp.ip(".".join(str(b) for b in raw)).split(".")
                )
            val = " ".join(f"{b:02X}" for b in raw) + (" " if raw else "")
        elif typ == "STRING":
            if any(oid == p or oid.startswith(p) for p in SERIAL):
                val = mp.serial(val)
            elif any(oid == p or oid.startswith(p) for p in FREE_TEXT):
                val = mp.text(
                    mp.name(
                        val,
                        "host"
                        if oid.endswith((".5.0",)) or ".4.1.1.9." in oid
                        else "desc",
                    )
                )
            elif oid.startswith(".1.3.6.1.4.1."):
                bare = val.strip().strip('"')
                if bare and not (
                    VERSIONISH.match(bare)
                    or MODELISH.match(bare)
                    or IFNAMEISH.match(bare)
                ):
                    val = mp.name(val, "text")
                val = mp.text(val)
            else:
                val = mp.text(val)
        else:
            val = mp.text(val)
        out.append(f"{oid} = {typ}: {val}" if val != "" else f"{oid} = {typ}: ")
    return out


def main(paths: list[str]) -> None:
    files = {p: Path(p).read_text(errors="replace").splitlines() for p in paths}
    ips: set[str] = set()
    macs: set[str] = set()
    for lines in files.values():
        ips |= known_ips(lines)
        macs |= known_macs(lines)
    mp = Mapper()
    mp.known_ips = ips
    # Serials first, so a serial quoted in another column (a description,
    # an HA table) is replaced there too.
    for lines in files.values():
        for line in lines:
            m = LINE.match(line)
            if (
                m
                and m.group(2) == "STRING"
                and any(m.group(1) == p or m.group(1).startswith(p) for p in SERIAL)
            ):
                mp.serial(m.group(3))
    for p, lines in files.items():
        Path(p).write_text("\n".join(anonymise(lines, mp, ips, macs)) + "\n")
        print(p, len(lines))
    print(
        "serials:",
        len(mp.serials),
        "names:",
        len(mp.names),
        "ips:",
        len(mp.ips),
        "macs:",
        len(mp.macs),
    )


if __name__ == "__main__":
    main(sys.argv[1:])
