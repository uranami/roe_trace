#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace roe::trace_lifecycle {

inline std::atomic<unsigned> active_callbacks{};
inline std::atomic<bool> unload_requested{};

struct CallbackScope {
    CallbackScope() { active_callbacks.fetch_add(1, std::memory_order_seq_cst); }
    ~CallbackScope() { active_callbacks.fetch_sub(1, std::memory_order_seq_cst); }
    CallbackScope(const CallbackScope&) = delete;
    CallbackScope& operator=(const CallbackScope&) = delete;
};

inline void RequestUnload() { unload_requested.store(true); }

struct CodeRange { std::uintptr_t begin; std::size_t size; };

// After all hooks are disabled, retain trampolines until callbacks AND their
// return/entry tails have left. Any inaccessible thread/context fails closed.
bool ThreadsOutsideCode(std::span<const CodeRange> ranges);

// Removes this statically linked SafetyHook copy's VEH, not another module's.
// Call only after the last disable/reset operation; the handler is counted too.
bool RemoveSafetyHookHandler();

// Includes MidHook's private stubs and trampolines as well as InlineHooks.
void AppendSafetyHookCodeRanges(std::vector<CodeRange>& ranges);

} // namespace roe::trace_lifecycle
