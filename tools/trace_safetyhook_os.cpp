// Build the bundled Windows implementation with explicit ownership of its
// exception callback. No vendored source edits and no process-wide VEH removal.
#include <windows.h>
#include "trace_lifecycle.hpp"
#include <algorithm>
#include <mutex>

namespace {
std::atomic<PVOID> owned_handler{};
PVECTORED_EXCEPTION_HANDLER original_handler = nullptr;
std::mutex allocation_mutex;
std::vector<roe::trace_lifecycle::CodeRange> allocations;

LPVOID WINAPI TraceVirtualAlloc(LPVOID address,SIZE_T size,DWORD type,DWORD protect) {
    const auto result=VirtualAlloc(address,size,type,protect);
    if (result) {
        std::lock_guard lock(allocation_mutex);
        allocations.push_back({reinterpret_cast<std::uintptr_t>(result),size});
    }
    return result;
}
BOOL WINAPI TraceVirtualFree(LPVOID address,SIZE_T size,DWORD type) {
    const auto result=VirtualFree(address,size,type);
    if (result && type==MEM_RELEASE) {
        std::lock_guard lock(allocation_mutex);
        std::erase_if(allocations,[&](const auto& range) {
            return range.begin==reinterpret_cast<std::uintptr_t>(address);
        });
    }
    return result;
}

LONG CALLBACK CountedTrapHandler(PEXCEPTION_POINTERS exception) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    return original_handler(exception);
}
PVOID TraceAddHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler) {
    original_handler = handler;
    const auto result = AddVectoredExceptionHandler(first, CountedTrapHandler);
    owned_handler.store(result);
    return result;
}
ULONG TraceRemoveHandler(PVOID handle) {
    auto expected = handle;
    if (!owned_handler.compare_exchange_strong(expected, nullptr)) return 1;
    const auto result = RemoveVectoredExceptionHandler(handle);
    if (!result) owned_handler.store(handle);
    return result;
}
}

#define AddVectoredExceptionHandler TraceAddHandler
#define RemoveVectoredExceptionHandler TraceRemoveHandler
#define VirtualAlloc TraceVirtualAlloc
#define VirtualFree TraceVirtualFree
#include "../third_party/safetyhook/src/os.windows.cpp"
#undef AddVectoredExceptionHandler
#undef RemoveVectoredExceptionHandler
#undef VirtualAlloc
#undef VirtualFree

namespace roe::trace_lifecycle {
bool RemoveSafetyHookHandler() {
    const auto handle = owned_handler.load();
    return !handle || TraceRemoveHandler(handle) != 0;
}
void AppendSafetyHookCodeRanges(std::vector<CodeRange>& ranges) {
    std::lock_guard lock(allocation_mutex);
    ranges.insert(ranges.end(),allocations.begin(),allocations.end());
}
}
