#include "../source/monitor_player_filter.hpp"

#include <cassert>

int main() {
    using MonitorPlayerFilter::IncludeNode;

    /* Older schemas without the optional field retain their name list. */
    assert(IncludeNode(false, nullptr));
    assert(IncludeNode(false, "false"));

    /* Current GraphQL/REST schemas include only live nodes. */
    assert(IncludeNode(true, "true"));
    assert(IncludeNode(true, " true ,"));
    assert(!IncludeNode(true, "false"));
    assert(!IncludeNode(true, "false}"));
    assert(!IncludeNode(true, "null"));
    assert(!IncludeNode(true, nullptr));
    assert(!IncludeNode(true, "trueish"));

    /* UDP NetworkInfo is a fixed-size node array; stale entries at indices
     * beyond nodeCount must not leak names from earlier room occupants. */
    using MonitorPlayerFilter::IncludeConnectedSlot;
    assert(IncludeConnectedSlot(0, 1, true));
    assert(!IncludeConnectedSlot(1, 1, true));
    assert(!IncludeConnectedSlot(0, 1, false));
    assert(!IncludeConnectedSlot(0, 0, true));
    return 0;
}
