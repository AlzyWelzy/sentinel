"""Drive a QEMU VM's console through its monitor socket: type text and take
screenshots. For bootstrapping test VMs that have no cloud-init (NetBSD's
live image): log in on the console and enable SSH, like a person would.

    python3 qemu_console.py <monitor.sock> shot <out.png>
    python3 qemu_console.py <monitor.sock> type '<text>'     (\\n presses Enter)
"""

import socket
import sys
import time

KEYS = {
    " ": "spc", "\n": "ret", "-": "minus", "=": "equal", "/": "slash", ".": "dot",
    ",": "comma", ";": "semicolon", "'": "apostrophe", "`": "grave_accent",
    "\\": "backslash", "[": "bracket_left", "]": "bracket_right", "\t": "tab",
}
SHIFTED = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7", "*": "8",
    "(": "9", ")": "0", "_": "minus", "+": "equal", ":": "semicolon", '"': "apostrophe",
    "~": "grave_accent", "|": "backslash", "{": "bracket_left", "}": "bracket_right",
    "<": "comma", ">": "dot", "?": "slash",
}


def key_for(ch: str) -> str:
    if ch.isalpha() and ch.isascii():
        return f"shift-{ch.lower()}" if ch.isupper() else ch
    if ch.isdigit():
        return ch
    if ch in KEYS:
        return KEYS[ch]
    if ch in SHIFTED:
        base = SHIFTED[ch]
        return f"shift-{KEYS.get(base, base)}" if base in KEYS.values() else f"shift-{base}"
    raise ValueError(f"no key mapping for {ch!r}")


def monitor(path: str, commands: list[str], delay: float = 0.03) -> None:
    s = socket.socket(socket.AF_UNIX)
    s.connect(path)
    s.settimeout(2)
    time.sleep(0.2)
    s.recv(65536)  # banner
    for cmd in commands:
        s.sendall(cmd.encode() + b"\n")
        time.sleep(delay)
    time.sleep(0.5)
    s.close()


if __name__ == "__main__":
    sock, action, arg = sys.argv[1], sys.argv[2], sys.argv[3]
    if action == "shot":
        monitor(sock, [f"screendump {arg} -f png"])
    elif action == "type":
        text = arg.encode().decode("unicode_escape")
        monitor(sock, [f"sendkey {key_for(c)}" for c in text])
