#pragma once

#include <atomic>
#include <cstdint>

/* A refresh request owns a generation token. Once a newer request is queued,
 * older blocking network responses must not publish into the shared snapshot. */
namespace MonitorTargetGeneration {

using Value = std::uint32_t;

class Gate {
public:
    Value Advance() { return generation_.fetch_add(1) + 1; }
    Value Capture() const { return generation_.load(); }
    bool IsCurrent(Value captured) const { return Capture() == captured; }

private:
    std::atomic<Value> generation_{0};
};

} // namespace MonitorTargetGeneration
