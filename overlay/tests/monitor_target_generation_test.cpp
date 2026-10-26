#include "../source/monitor_target_generation.hpp"

#include <cassert>

int main() {
    MonitorTargetGeneration::Gate gate;

    /* A response may publish only while it still owns the latest request. */
    const auto shanghaiRequest = gate.Advance();
    assert(gate.IsCurrent(shanghaiRequest));

    /* Switching to another server invalidates the in-flight old response. */
    const auto denmarkRequest = gate.Advance();
    assert(!gate.IsCurrent(shanghaiRequest));
    assert(gate.IsCurrent(denmarkRequest));

    /* A later refresh supersedes even a same-target response. */
    const auto newerRefresh = gate.Advance();
    assert(!gate.IsCurrent(denmarkRequest));
    assert(gate.IsCurrent(newerRefresh));
    return 0;
}
