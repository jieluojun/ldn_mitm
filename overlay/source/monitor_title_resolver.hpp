#pragma once

#include <stddef.h>
#include <string.h>

/* Resolve title IDs for games whose LDN contentId is the all-F sentinel.
 * advertiseData is the room's own hexadecimal LDN payload; no local process
 * state is used, so rooms from different games cannot inherit the foreground
 * application's title by accident. */
namespace MonitorTitleResolver {

static constexpr size_t kAdvertiseDataMaxBytes = 384;
static constexpr size_t kAdvertiseDataMaxHex = kAdvertiseDataMaxBytes * 2;

inline int HexDigit(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

inline bool NormalizeAdvertiseHex(const char *src, char *out, size_t outN,
                                  size_t *outLen) {
    if (outLen)
        *outLen = 0;
    if (!src || !out || outN == 0)
        return false;

    size_t len = 0;
    for (const char *p = src; *p; ++p) {
        const int digit = HexDigit(*p);
        if (digit >= 0) {
            if (len + 1 >= outN) {
                out[0] = 0;
                return false;
            }
            out[len++] = "0123456789abcdef"[digit];
        } else if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' ||
                   *p == ':' || *p == '-') {
            continue;
        } else {
            out[0] = 0;
            return false;
        }
    }
    out[len] = 0;
    if (outLen)
        *outLen = len;
    return len != 0 && (len & 1) == 0;
}

inline bool HexSpanContains(const char *begin, const char *end,
                            const char *needle) {
    if (!begin || !end || !needle || end < begin)
        return false;
    const size_t needleLen = strlen(needle);
    const size_t spanLen = (size_t)(end - begin);
    if (needleLen == 0)
        return true;
    if (needleLen > spanLen)
        return false;
    for (size_t i = 0; i + needleLen <= spanLen; ++i) {
        if (memcmp(begin + i, needle, needleLen) == 0)
            return true;
    }
    return false;
}

inline bool CopyTitleId(const char *titleId, char *out, size_t outN) {
    if (!titleId || !out || outN < 17)
        return false;
    memcpy(out, titleId, 17);
    return true;
}

/* Returns false when the advertisement is absent or does not match a known
 * signature. The caller must then show the safe unknown-game fallback. */
inline bool ResolveAdvertisedTitleId(const char *advertiseData,
                                     const char *hostPlayerName,
                                     char *outTitleId, size_t outN) {
    if (outTitleId && outN > 0)
        outTitleId[0] = 0;
    if (!outTitleId || outN < 17)
        return false;

    char hex[kAdvertiseDataMaxHex + 1] = {};
    size_t hexLen = 0;
    if (!NormalizeAdvertiseHex(advertiseData, hex, sizeof(hex), &hexLen))
        return false;

    /* DRAGON BALL FighterZ: advertiseData == ffff0000. */
    if (hexLen == 8 && strcmp(hex, "ffff0000") == 0)
        return CopyTitleId("0100A250097F0000", outTitleId, outN);

    /* Rocket League advertises a JSON object (7b = '{', 7d = '}'). */
    if (hexLen >= 4 && hex[0] == '7' && hex[1] == 'b' &&
        hex[hexLen - 2] == '7' && hex[hexLen - 1] == 'd')
        return CopyTitleId("01005EE0036EC000", outTitleId, outN);

    static const char kDelimiter[] = "00000004";
    const size_t delimiterLen = sizeof(kDelimiter) - 1;
    size_t delimiterCount = 0;
    for (const char *p = hex; (p = strstr(p, kDelimiter)) != nullptr;
         p += delimiterLen)
        ++delimiterCount;
    const char *firstDelimiter = strstr(hex, kDelimiter);
    const char *firstPartEnd = firstDelimiter ? firstDelimiter : hex + hexLen;

    /* MONSTER HUNTER RISE has player/rank sections after two delimiters. */
    if (delimiterCount >= 2 &&
        HexSpanContains(hex, firstPartEnd, "0000000008100000") &&
        HexSpanContains(hex, firstPartEnd, "8b9000"))
        return CopyTitleId("0100B04011742000", outTitleId, outN);

    /* Monster Hunter Stories 2 shares the common prefix, but has 0a0000. */
    if (HexSpanContains(hex, firstPartEnd, "0000000008100000") &&
        HexSpanContains(hex, firstPartEnd, "0a0000"))
        return CopyTitleId("0100E21011446000", outTitleId, outN);

    /* Minecraft stores the host name as UTF-8 starting at hex offset 32. */
    if (hostPlayerName && hostPlayerName[0] && hexLen > 32 &&
        ((hexLen - 32) & 1) == 0) {
        char decoded[96] = {};
        size_t decodedLen = 0;
        for (size_t i = 32; i + 1 < hexLen; i += 2) {
            const int hi = HexDigit(hex[i]);
            const int lo = HexDigit(hex[i + 1]);
            if (hi < 0 || lo < 0)
                return false;
            const unsigned char byte = (unsigned char)((hi << 4) | lo);
            if (byte == 0)
                break;
            if (decodedLen + 1 >= sizeof(decoded))
                return false;
            decoded[decodedLen++] = (char)byte;
        }
        decoded[decodedLen] = 0;
        if (decodedLen != 0 && strcmp(decoded, hostPlayerName) == 0)
            return CopyTitleId("0100D71004694000", outTitleId, outN);
    }

    return false;
}

} // namespace MonitorTitleResolver
