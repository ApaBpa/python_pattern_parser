import re
import sys
from pathlib import Path
from textwrap import dedent

UNUSED = 0xFFFF
_HEX_DIGITS = set("0123456789abcdefABCDEF")

def parse_snort_content(s: str) -> bytes:
    """
    Parse the Snort-style 'content' representation used in the pattern file:
      - ASCII outside |...| is literal (1 char -> 1 byte, must be <= 0xFF)
      - Inside |...| is hex bytes (pairs of hex digits), whitespace ignored
    """
    out = bytearray()
    i = 0
    in_hex = False
    hex_buf = []

    def flush_hex_buf():
        if not hex_buf:
            return
        # Remove all whitespace (already excluded below) and parse pairs.
        if len(hex_buf) % 2 != 0:
            raise ValueError(f"Odd number of hex digits in hex block: {''.join(hex_buf)!r}")
        for j in range(0, len(hex_buf), 2):
            out.append(int(hex_buf[j] + hex_buf[j + 1], 16))
        hex_buf.clear()

    while i < len(s):
        ch = s[i]

        if ch == "|":
            if in_hex:
                # end hex block
                flush_hex_buf()
                in_hex = False
            else:
                # begin hex block
                in_hex = True
            i += 1
            continue

        if in_hex:
            # Hex block: accept hex digits and whitespace; ignore whitespace
            if ch.isspace():
                i += 1
                continue
            if ch not in _HEX_DIGITS:
                raise ValueError(f"Non-hex character {ch!r} inside hex block in: {s!r}")
            hex_buf.append(ch)
            i += 1
            continue

        # ASCII mode
        b = ord(ch)
        if b > 0xFF:
            raise ValueError(f"Non 8-bit character {ch!r} in: {s!r}")
        out.append(b)
        i += 1

    if in_hex:
        raise ValueError(f"Unterminated hex block (missing closing '|') in: {s!r}")

    return bytes(out)

def extract_patterns(path: Path):
    patterns: list[bytes] = []
    max_len = 0
    used_bytes = set()

    with path.open(encoding="utf-8", newline="") as f:
        for line in f:
            # Preserve significant spaces/tabs; only drop line endings.
            raw = line.rstrip("\n").rstrip("\r")
            if raw == "":
                continue

            pbytes = parse_snort_content(raw)
            patterns.append(pbytes)
            max_len = max(max_len, len(pbytes))
            used_bytes.update(pbytes)

    return patterns, max_len, used_bytes

def generate_patterns_hpp(patterns, max_len=512, header_guard="PATTERNS_GENERATED_H"):
    def pattern_bytes_literal(p: bytes):
        return ", ".join(f"0x{b:02x}" for b in p)

    lines = []
    lines.append("#include <cstddef>")
    lines.append("#include <cstdint>")
    lines.append(f"#ifndef {header_guard}")
    lines.append(f"#define {header_guard}")
    lines.append("")
    lines.append("#include <cstdint>")
    lines.append("")
    max_len = max(1, max_len)  # Ensure at least size 1
    lines.append(f"constexpr std::size_t MAX_PATTERN_LEN = {max_len};   // max length of any pattern")
    lines.append("")
    lines.append("struct Pattern {")
    lines.append("    std::uint16_t id;       // pattern ID")
    lines.append("    std::uint16_t length;   // number of valid bytes in 'bytes'")
    lines.append("    std::uint8_t  bytes[MAX_PATTERN_LEN];")
    lines.append("};")
    lines.append("")
    lines.append(f"constexpr Pattern PATTERNS[] = {{")

    for idx, p in enumerate(patterns):
        byte_list = pattern_bytes_literal(p)
        # Missing elements in bytes[] are zero-initialized automatically
        lines.append(f"    {{ {idx}, {len(p)}, {{ {byte_list} }} }},")
    lines.append("};")
    lines.append("")
    lines.append("constexpr std::size_t NUM_PATTERNS = sizeof(PATTERNS) / sizeof(PATTERNS[0]);")
    lines.append("")
    lines.append(f"#endif // {header_guard}")

    return "\n".join(lines)

def generate_alphabet_hpp(used_bytes, header_guard="PATTERN_ALPHABET_H"):
    used_sorted = sorted(used_bytes)
    k = len(used_sorted)

    # Build byte -> index map
    byte_to_idx = [UNUSED] * 256
    for idx, b in enumerate(used_sorted):
        byte_to_idx[b] = idx

    # Format helpers
    def fmt_u8_list(vals, per_line=16):
        out = []
        for i in range(0, len(vals), per_line):
            chunk = ", ".join(f"0x{v:02X}" for v in vals[i:i+per_line])
            out.append("    " + chunk + ("," if i + per_line < len(vals) else ""))
        return "\n".join(out)

    def fmt_u16_list(vals, per_line=16):
        out = []
        for i in range(0, len(vals), per_line):
            chunk = ", ".join(f"0x{v:04X}" for v in vals[i:i+per_line])
            out.append("    " + chunk + ("," if i + per_line < len(vals) else ""))
        return "\n".join(out)

    lines = []
    lines.append(f"#ifndef {header_guard}")
    lines.append(f"#define {header_guard}")
    lines.append("")
    lines.append("#include <cstddef>")
    lines.append("#include <cstdint>")
    lines.append("")
    lines.append(f"constexpr std::size_t ALPHABET_SIZE = {k};")
    lines.append(f"constexpr std::uint16_t BYTE_UNUSED = 0x{UNUSED:04X};")
    lines.append("")
    lines.append(f"static constexpr std::uint8_t USED_BYTES[ALPHABET_SIZE] = {{")
    lines.append(fmt_u8_list(used_sorted))
    lines.append("};")
    lines.append("")
    lines.append("static constexpr std::uint16_t BYTE_TO_IDX[256] = {")
    lines.append(fmt_u16_list(byte_to_idx))
    lines.append("};")
    lines.append("")
    lines.append(f"#endif // {header_guard}")

    return "\n".join(lines)

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <input> <patterns_name> <alphabet_name>")
        sys.exit(1)

    in_path = Path(sys.argv[1])
    patterns_out = Path(sys.argv[2])
    alphabet_out = Path(sys.argv[3])

    patterns, max_pattern_length, used_bytes = extract_patterns(in_path)
    
    patterns_hpp = generate_patterns_hpp(patterns, max_pattern_length)
    alphabet_hpp = generate_alphabet_hpp(used_bytes)

    patterns_out.write_text(patterns_hpp, encoding="utf-8")
    alphabet_out.write_text(alphabet_hpp, encoding="utf-8")

    print(f"Wrote {patterns_out} ({len(patterns)} patterns, max_len={max_pattern_length})")
    print(f"Wrote {alphabet_out} (ALPHABET_SIZE={len(used_bytes)})")

if __name__ == "__main__":
    main()