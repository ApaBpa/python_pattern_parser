import re
import sys
from pathlib import Path
from textwrap import dedent

def extract_patterns(path: Path):
    patterns = []
    max_len = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped:  # Non-empty line
                patterns.append(stripped)
                max_len = max(max_len, len(stripped))
            else:
                continue
    return patterns, max_len

def generate_cpp(patterns, max_len=512, header_guard="PATTERNS_GENERATED_H"):
    def pattern_bytes_literal(p):
        return ", ".join(f"0x{ord(c):02x}" for c in p)

    lines = []

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

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.txt> <output.hpp>")
        sys.exit(1)

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    patterns, max_pattern_length = extract_patterns(in_path)
    cpp_code = generate_cpp(patterns, max_pattern_length)
    out_path.write_text(cpp_code, encoding="utf-8")

if __name__ == "__main__":
    main()