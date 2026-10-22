#include <windows.h>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

namespace {
HANDLE entered = nullptr;
HANDLE release_callback = nullptr;
std::atomic<bool> block_next{};
volatile std::uint32_t mid_bias=5U; // keep real calls across DLL mutations
}

extern "C" __declspec(dllexport) __declspec(noinline)
std::uint32_t TraceTestTarget(std::uint32_t value) {
    if (block_next.exchange(false)) {
        SetEvent(entered);
        WaitForSingleObject(release_callback, 20000U);
    }
    return value + 10U;
}

extern "C" __declspec(dllexport) __declspec(noinline)
std::uint32_t TraceTestMidTarget(std::uint32_t value) {
    return value*3U+mid_bias;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    const auto dll = std::filesystem::absolute(argv[1]);
    // Call the exported address exactly, bypassing GCC's local constprop
    // clones of this small function when called with the literal 5.
    const auto mid_target=reinterpret_cast<std::uint32_t(*)(std::uint32_t)>(
        GetProcAddress(GetModuleHandleW(nullptr),"TraceTestMidTarget"));
    if (!mid_target) return 1;
    const auto name = dll.filename().wstring();
    const auto suffix = std::to_wstring(GetCurrentProcessId());
    const auto ready_name = L"Local\\ROE.Trace.TestReady." + suffix;
    const auto event_name = L"Local\\ROE.Trace.Unload." + suffix;
    const auto ready = CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str());
    entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    release_callback = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ready || !entered || !release_callback) return 1;
    for (int cycle = 0; cycle < 3; ++cycle) {
        ResetEvent(ready);
        ResetEvent(entered);
        ResetEvent(release_callback);
        if (!LoadLibraryW(dll.c_str()) || WaitForSingleObject(ready, 5000U) != WAIT_OBJECT_0) return 1;
        if (TraceTestTarget(5U) != 16U) return 1; // real InlineHook + counted VEH
        const auto hooked_mid=mid_target(5U);
        if (hooked_mid != 23U) {
            std::cerr<<"MidHook host result="<<hooked_mid<<" expected=23\n"; return 1;
        }
        const auto unload = OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name.c_str());
        if (!unload) return 1;
        block_next.store(true);
        std::atomic<std::uint32_t> result{};
        std::thread callback([&] { result.store(TraceTestTarget(7U)); });
        if (WaitForSingleObject(entered, 5000U) != WAIT_OBJECT_0) {
            SetEvent(release_callback);
            callback.join();
            return 1;
        }
        SetEvent(unload);
        // First round tests timeout/fail-closed and explicit retry; later
        // rounds test draining a callback before the initial deadline.
        Sleep(cycle == 0 ? 6200U : 250U);
        const bool retained = GetModuleHandleW(name.c_str()) != nullptr;
        SetEvent(release_callback);
        callback.join();
        if (!retained || result.load() != 18U) return 1;
        if (cycle == 0) { Sleep(100U); SetEvent(unload); }
        CloseHandle(unload);
        const auto deadline = GetTickCount64() + 10000U;
        while (GetModuleHandleW(name.c_str()) && GetTickCount64() < deadline) Sleep(20U);
        if (GetModuleHandleW(name.c_str()) || TraceTestTarget(5U) != 15U) return 1;
        if (mid_target(5U) != 20U) {
            std::cerr<<"MidHook original behavior not restored\n"; return 1;
        }
        std::cout << "load/unload cycle " << cycle + 1 << " passed\n";
    }
    CloseHandle(ready);
    CloseHandle(entered);
    CloseHandle(release_callback);
    return 0;
}
