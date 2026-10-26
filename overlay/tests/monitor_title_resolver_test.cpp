#include "../source/monitor_title_resolver.hpp"

#include <assert.h>
#include <string.h>

using MonitorTitleResolver::ResolveAdvertisedTitleId;

static void ExpectResolved(const char *advertiseData, const char *hostName,
                          const char *expectedTitleId) {
    char titleId[17] = {};
    assert(ResolveAdvertisedTitleId(advertiseData, hostName,
                                    titleId, sizeof(titleId)));
    assert(strcmp(titleId, expectedTitleId) == 0);
}

static void ExpectUnresolved(const char *advertiseData, const char *hostName) {
    char titleId[17] = "not-a-title-id";
    assert(!ResolveAdvertisedTitleId(advertiseData, hostName,
                                     titleId, sizeof(titleId)));
    assert(titleId[0] == 0);
}

int main() {
    ExpectResolved("ffff0000", nullptr, "0100A250097F0000");
    ExpectResolved("7b7d", nullptr, "01005EE0036EC000");
    ExpectResolved("00000000081000008b9000"
                   "00000004"
                   "1234"
                   "00000004"
                   "5678",
                   nullptr, "0100B04011742000");
    ExpectResolved("00000000081000000a0000"
                   "00000004"
                   "1234",
                   nullptr, "0100E21011446000");
    ExpectResolved("00112233445566778899aabbccddeeff4d6961", "Mia",
                   "0100D71004694000");

    /* Case/spacing normalization is harmless, while partial signatures are
     * not promoted to a title. Unknown sentinels must remain unknown. */
    ExpectResolved("FF FF 00 00", nullptr, "0100A250097F0000");
    ExpectUnresolved("00000000081000008b9000"
                     "00000004"
                     "1234",
                     nullptr); // Rise signature is missing its second delimiter.
    ExpectUnresolved("00112233445566778899aabbccddeeff4d6961", "Not-Mia");
    ExpectUnresolved("11223344", nullptr);
    return 0;
}
