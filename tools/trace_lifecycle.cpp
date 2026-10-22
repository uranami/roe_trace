#include <windows.h>
#include <tlhelp32.h>

#include "trace_lifecycle.hpp"

#include <array>

namespace roe::trace_lifecycle {
namespace {
bool Inside(std::uintptr_t address, std::span<const CodeRange> ranges) {
    for (const auto& range : ranges)
        if (address >= range.begin && address - range.begin < range.size) return true;
    return false;
}

bool InspectThread(HANDLE thread, std::span<const CodeRange> ranges) {
    // No heap allocation, logging or user mutex while another thread is paused.
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(thread, &context)) return false;
    const std::array<std::uintptr_t, 17> registers{
        context.Rip, context.Rax, context.Rbx, context.Rcx, context.Rdx,
        context.Rsi, context.Rdi, context.Rbp, context.R8, context.R9,
        context.R10, context.R11, context.R12, context.R13, context.R14,
        context.R15, context.Rsp};
    for (auto value : registers) if (Inside(value, ranges)) return false;
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery(reinterpret_cast<void*>(context.Rsp), &region, sizeof(region)) ||
        region.State != MEM_COMMIT || (region.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
    const auto end = reinterpret_cast<std::uintptr_t>(region.BaseAddress) + region.RegionSize;
    if (end < context.Rsp || end - context.Rsp > 2U * 1024U * 1024U) return false;
    std::array<std::uintptr_t, 512> words{};
    for (auto cursor = context.Rsp; cursor < end;) {
        const auto bytes = (end - cursor < sizeof(words)) ? end - cursor : sizeof(words);
        SIZE_T read = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(cursor),
                               words.data(), bytes, &read) || read != bytes) return false;
        for (std::size_t i = 0; i < read / sizeof(std::uintptr_t); ++i)
            if (Inside(words[i], ranges)) return false;
        cursor += bytes;
    }
    return true;
}
} // namespace

bool ThreadsOutsideCode(std::span<const CodeRange> ranges) {
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    bool safe = Thread32First(snapshot, &entry) != FALSE;
    if (safe) do {
        if (entry.th32OwnerProcessID != GetCurrentProcessId() ||
            entry.th32ThreadID == GetCurrentThreadId()) continue;
        const auto thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
            THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
        if (!thread) {
            if (GetLastError() == ERROR_INVALID_PARAMETER) continue; // exited
            safe = false;
            break;
        }
        const auto suspended = SuspendThread(thread);
        if (suspended == static_cast<DWORD>(-1)) {
            DWORD exit_code = STILL_ACTIVE;
            safe = GetExitCodeThread(thread, &exit_code) && exit_code != STILL_ACTIVE;
        } else {
            safe = InspectThread(thread, ranges);
            if (ResumeThread(thread) == static_cast<DWORD>(-1)) safe = false;
        }
        CloseHandle(thread);
        if (!safe) break;
    } while (Thread32Next(snapshot, &entry));
    if (safe && GetLastError() != ERROR_NO_MORE_FILES) safe = false;
    CloseHandle(snapshot);
    return safe && active_callbacks.load() == 0U;
}
} // namespace roe::trace_lifecycle
