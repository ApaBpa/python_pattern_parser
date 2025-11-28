#ifndef PATTERNS_GENERATED_H
#define PATTERNS_GENERATED_H

#include <cstdint>

constexpr std::size_t MAX_PATTERN_LEN = 9000;

struct Pattern {
    std::uint16_t id;       // pattern ID
    std::uint16_t length;   // number of valid bytes in 'bytes'
    std::uint8_t  bytes[MAX_PATTERN_LEN];
};

constexpr Pattern PATTERNS[] = {
    { 0, 5, { 0x62, 0x72, 0x61, 0x69, 0x6e } },
    { 1, 6, { 0x64, 0x61, 0x6d, 0x61, 0x67, 0x65 } },
    { 2, 9, { 0x6f, 0x76, 0x65, 0x72, 0x39, 0x30, 0x30, 0x30, 0x21 } },
};

constexpr std::size_t NUM_PATTERNS = sizeof(PATTERNS) / sizeof(PATTERNS[0]);

#endif // PATTERNS_GENERATED_H