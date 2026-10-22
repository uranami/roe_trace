#if !defined(_WIN32)
#error "roe_injector is a Windows-only helper"
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <cwchar>
#include <cstdint>
#include <iterator>
#include <limits>

namespace {

void PrintError(const wchar_t* operation) {
    std::wcerr << operation << L" failed, Win32 error=" << GetLastError() << L"\n";
}

// 1=present, 0=absent, -1=inspection failed (never treat access denied as unloaded).
int FindModule(DWORD pid, const wchar_t* name, MODULEENTRY32W* result = nullptr) {
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 5; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
        Sleep(10);
    }
    if (snapshot == INVALID_HANDLE_VALUE) return -1;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    int found = 0;
    if (!Module32FirstW(snapshot, &entry)) found = -1;
    else do {
        if (_wcsicmp(entry.szModule, name) == 0) {
            if (result) *result = entry;
            found = 1;
            break;
        }
    } while (Module32NextW(snapshot, &entry));
    if (found == 0 && GetLastError() != ERROR_NO_MORE_FILES) found = -1;
    CloseHandle(snapshot);
    return found;
}

bool ParsePid(const wchar_t* text, DWORD& pid) {
    if (!text || !*text) return false;
    unsigned long long value = 0;
    for (const auto* c = text; *c; ++c) {
        if (*c < L'0' || *c > L'9') return false;
        value = value * 10U + (*c - L'0');
        if (value > std::numeric_limits<DWORD>::max()) return false;
    }
    pid = static_cast<DWORD>(value);
    return pid != 0U;
}

bool IsSupportedClient(HANDLE process) {
    wchar_t path[32768]{};
    DWORD size = static_cast<DWORD>(std::size(path));
    BOOL wow64 = TRUE;
    if (!QueryFullProcessImageNameW(process, 0, path, &size) ||
        !IsWow64Process(process, &wow64) || wow64) return false;
    const std::filesystem::path executable(path);
    const auto name = executable.filename().wstring();
    return (_wcsicmp(name.c_str(), L"Europa_Client_tp6_unpacked.exe") == 0 ||
            _wcsicmp(name.c_str(), L"Europa_Client.exe") == 0) &&
        _wcsicmp(executable.parent_path().filename().c_str(), L"XVersion") == 0;
}

LPTHREAD_START_ROUTINE RemoteLoadLibrary(DWORD pid) {
    const auto kernel32 = GetModuleHandleW(L"kernel32.dll");
    const auto function = kernel32 ? GetProcAddress(kernel32, "LoadLibraryW") : nullptr;
    HMODULE owner = nullptr;
    if (!function || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(function), &owner)) return nullptr;
    wchar_t owner_path[MAX_PATH]{};
    if (!GetModuleFileNameW(owner, owner_path, MAX_PATH)) return nullptr;
    MODULEENTRY32W remote{};
    if (FindModule(pid, std::filesystem::path(owner_path).filename().c_str(), &remote) != 1) return nullptr;
    const auto offset = reinterpret_cast<std::uintptr_t>(function) - reinterpret_cast<std::uintptr_t>(owner);
    if (offset >= remote.modBaseSize) return nullptr;
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(remote.modBaseAddr + offset);
}

std::wstring QuoteArgument(const std::wstring& value) {
    std::wstring quoted = L"\"";
    std::size_t backslashes = 0;
    for (const wchar_t character : value) {
        if (character == L'\\') {
            ++backslashes;
            continue;
        }
        if (character == L'\"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(L'\"');
            backslashes = 0;
            continue;
        }
        quoted.append(backslashes, L'\\');
        backslashes = 0;
        quoted.push_back(character);
    }
    quoted.append(backslashes * 2, L'\\');
    quoted.push_back(L'\"');
    return quoted;
}

bool InjectDll(HANDLE process, const std::wstring& dll_path, bool suspended_startup = false) {
    const auto bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    void* remote_path = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (remote_path == nullptr) {
        PrintError(L"VirtualAllocEx");
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_path, dll_path.c_str(), bytes, &written) ||
        written != bytes) {
        PrintError(L"WriteProcessMemory");
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        return false;
    }

    auto load_library = RemoteLoadLibrary(GetProcessId(process));
    if (!load_library && suspended_startup) {
        // Preserve the original suspended-start launcher: the first remote
        // thread initializes the loader before invoking this system export.
        const auto kernel32 = GetModuleHandleW(L"kernel32.dll");
        load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            kernel32 ? GetProcAddress(kernel32, "LoadLibraryW") : nullptr);
    }
    if (load_library == nullptr) {
        PrintError(L"GetProcAddress(LoadLibraryW)");
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = CreateRemoteThread(process, nullptr, 0,
        load_library, remote_path, 0, nullptr);
    if (thread == nullptr) {
        PrintError(L"CreateRemoteThread");
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        return false;
    }

    const DWORD wait_result = WaitForSingleObject(thread, 15000);
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    CloseHandle(thread);
    // Never free the argument while a timed-out LoadLibrary thread may read it.
    if (wait_result == WAIT_OBJECT_0) VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
    const auto dll_name = std::filesystem::path(dll_path).filename().wstring();
    MODULEENTRY32W loaded{};
    if (wait_result != WAIT_OBJECT_0 ||
        FindModule(GetProcessId(process), dll_name.c_str(), &loaded) != 1 ||
        _wcsicmp(loaded.szExePath, dll_path.c_str()) != 0) {
        std::wcerr << L"LoadLibraryW did not load the trace DLL (wait=" << wait_result
                   << L", exit=" << exit_code << L")\n";
        return false;
    }
    return true;
}

int ControlTrace(int argc, wchar_t** argv) {
    const bool unload = std::wstring(argv[1]) == L"--unload";
    DWORD pid = 0;
    if (argc != (unload ? 3 : 4) || !ParsePid(argv[2], pid)) {
        std::wcerr << L"usage: roe_injector.exe --unload <PID> | --attach <PID> <roe_trace.dll>\n";
        return 2;
    }
    const DWORD access = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE |
        (unload ? 0U : PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
    const auto process = OpenProcess(access, FALSE, pid);
    if (!process) { PrintError(L"OpenProcess"); return 1; }
    if (!IsSupportedClient(process)) {
        std::wcerr << L"Refusing: target is not a supported x64 XVersion client.\n";
        CloseHandle(process);
        return 2;
    }
    const auto present = FindModule(pid, L"roe_trace.dll");
    if (present < 0) { PrintError(L"Module enumeration"); CloseHandle(process); return 1; }
    if (unload) {
        if (present == 0) {
            std::wcout << L"roe_trace.dll is already absent.\n";
            CloseHandle(process);
            return 0;
        }
        const auto name = L"Local\\ROE.Trace.Unload." + std::to_wstring(pid);
        const auto event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
        if (!event) {
            std::wcerr << L"No cooperative unload endpoint. The old DLL requires one client restart; no forced FreeLibrary was attempted.\n";
            CloseHandle(process);
            return 1;
        }
        const auto requested = SetEvent(event);
        CloseHandle(event);
        if (!requested) { PrintError(L"SetEvent"); CloseHandle(process); return 1; }
        const auto deadline = GetTickCount64() + 15000U;
        do {
            if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) break;
            const auto remaining = FindModule(pid, L"roe_trace.dll");
            if (remaining == 0) {
                std::wcout << L"Trace DLL unloaded; client is still running.\n";
                CloseHandle(process);
                return 0;
            }
            if (remaining < 0) break;
            Sleep(100U);
        } while (GetTickCount64() < deadline);
        std::wcerr << L"Unload not confirmed. Check [UNLOAD] in roe_trace_<PID>.log; DLL may be retained for safety. No forced unload.\n";
        CloseHandle(process);
        return 1;
    }
    if (present != 0) {
        std::wcerr << L"Trace DLL already loaded. Unload it first; duplicate LoadLibrary would add a reference.\n";
        CloseHandle(process);
        return 1;
    }
    std::error_code error;
    const auto path = std::filesystem::absolute(argv[3], error).lexically_normal();
    if (error || !std::filesystem::is_regular_file(path) ||
        _wcsicmp(path.filename().c_str(), L"roe_trace.dll") != 0) {
        std::wcerr << L"Expected an existing roe_trace.dll.\n";
        CloseHandle(process);
        return 2;
    }
    const bool injected = InjectDll(process, path.wstring());
    CloseHandle(process);
    if (injected) std::wcout << L"Trace DLL injected into PID " << pid << L".\n";
    return injected ? 0 : 1;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && (std::wstring(argv[1]) == L"--unload" ||
                      std::wstring(argv[1]) == L"--attach")) return ControlTrace(argc, argv);
    if (argc < 3) {
        std::wcerr << L"usage: roe_injector.exe <client.exe> <trace.dll> [client args...]\n";
        return 2;
    }

    std::error_code error;
    const auto client_path = std::filesystem::absolute(argv[1], error);
    if (error || !std::filesystem::is_regular_file(client_path)) {
        std::wcerr << L"client executable not found: " << argv[1] << L"\n";
        return 2;
    }
    const auto trace_path = std::filesystem::absolute(argv[2], error);
    if (error || !std::filesystem::is_regular_file(trace_path)) {
        std::wcerr << L"trace DLL not found: " << argv[2] << L"\n";
        return 2;
    }

    std::wstring command_line = QuoteArgument(client_path.wstring());
    for (int index = 3; index < argc; ++index) {
        command_line.push_back(L' ');
        command_line += QuoteArgument(argv[index]);
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    std::wstring mutable_command_line = command_line;
    const auto working_directory = client_path.parent_path().parent_path();
    if (!CreateProcessW(client_path.c_str(), mutable_command_line.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, working_directory.c_str(), &startup, &process)) {
        PrintError(L"CreateProcessW");
        return 1;
    }

    if (!InjectDll(process.hProcess, trace_path.wstring(), true)) {
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 1;
    }

    if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
        PrintError(L"ResumeThread");
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 1;
    }

    const auto trace_stem = trace_path.stem().wstring();
    const auto log_name = trace_stem == L"roe_material_trace"
        ? (L"roe_material_trace_" + std::to_wstring(process.dwProcessId) + L".jsonl")
        : (L"roe_trace_" + std::to_wstring(process.dwProcessId) + L".log");
    const auto log_path = std::filesystem::temp_directory_path() / log_name;
    std::wcout << L"Started PID " << process.dwProcessId << L" with "
               << trace_path.wstring() << L"\n"
               << L"Trace log: " << log_path.wstring() << L"\n";
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 0;
}
