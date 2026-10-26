#pragma once

#include <cstddef>
#include <cstring>

namespace MonitorPlayerFilter {

/* Missing connection flags mean an older schema/REST shape: preserve its
 * previous behavior. If the field is present, only an explicit JSON true is
 * considered an occupied node; false/null/invalid values are stale slots. */
inline bool IncludeNode(bool hasConnectionFlag, const char *value) {
    if (!hasConnectionFlag)
        return true;
    if (!value)
        return false;
    while (*value == ' ' || *value == '\t' || *value == '\r' || *value == '\n')
        ++value;
    if (std::strncmp(value, "true", 4) != 0)
        return false;
    const char next = value[4];
    return next == '\0' || next == ',' || next == '}' || next == ']' ||
           next == ' ' || next == '\t' || next == '\r' || next == '\n';
}

/* NetworkInfo has a fixed eight-slot array, but only indices below nodeCount
 * belong to the current room. Later slots can retain names/flags from old peers. */
inline bool IncludeConnectedSlot(std::size_t index, std::size_t nodeCount,
                                 bool isConnected) {
    return index < nodeCount && isConnected;
}

} // namespace MonitorPlayerFilter
