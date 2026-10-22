#if !defined(_WIN32)
#error "roe_trace overlay is Windows-only"
#endif

#include "trace_overlay.hpp"

#include <windows.h>
#include <d3d12.h>
#include <dxgi1_4.h>

#include <imgui.h>
#include <imgui_impl_dx12.h>
#include <imgui_impl_win32.h>
#include <safetyhook.hpp>

#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <iterator>
#include <mutex>
#include <utility>
#include <vector>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace roe::trace_overlay {
namespace {

using PresentFn = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain*, UINT, UINT);
using Present1Fn = HRESULT(STDMETHODCALLTYPE*)(
    IDXGISwapChain1*, UINT, UINT, const DXGI_PRESENT_PARAMETERS*);
using ResizeBuffersFn = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain*, UINT,
                                                     UINT, UINT, DXGI_FORMAT,
                                                     UINT);
using ResizeBuffers1Fn = HRESULT(STDMETHODCALLTYPE*)(
    IDXGISwapChain3*, UINT, UINT, UINT, DXGI_FORMAT, UINT, const UINT*,
    IUnknown* const*);
using ExecuteCommandListsFn = void(STDMETHODCALLTYPE*)(
    ID3D12CommandQueue*, UINT, ID3D12CommandList* const*);
using CreateSwapChainFn = HRESULT(STDMETHODCALLTYPE*)(
    IDXGIFactory*, IUnknown*, DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**);
using CreateSwapChainForHwndFn = HRESULT(STDMETHODCALLTYPE*)(
    IDXGIFactory2*, IUnknown*, HWND, const DXGI_SWAP_CHAIN_DESC1*,
    const DXGI_SWAP_CHAIN_FULLSCREEN_DESC*, IDXGIOutput*, IDXGISwapChain1**);

safetyhook::InlineHook g_present_hook{};
safetyhook::InlineHook g_present1_hook{};
safetyhook::InlineHook g_resize_buffers_hook{};
safetyhook::InlineHook g_resize_buffers1_hook{};
safetyhook::InlineHook g_execute_command_lists_hook{};
safetyhook::InlineHook g_create_swap_chain_hook{};
safetyhook::InlineHook g_create_swap_chain_for_hwnd_hook{};

std::atomic<LogCallback> g_log_callback{};
std::atomic<double> g_coordinate_x{};
std::atomic<double> g_coordinate_y{};
std::atomic<double> g_coordinate_z{};
std::atomic<bool> g_coordinate_valid{};
std::atomic<bool> g_stopping{};
std::atomic<bool> g_panel_open{};
std::atomic<WNDPROC> g_original_wndproc{};
std::atomic<bool> g_window_chain_unsafe{};
safetyhook::InlineHook g_set_cursor_pos_hook{};
safetyhook::InlineHook g_clip_cursor_hook{};
struct WindowMessage { HWND window; UINT message; WPARAM wparam; LPARAM lparam; };
std::mutex g_window_messages_mutex;
std::vector<WindowMessage> g_window_messages;

std::mutex g_queue_mutex;
ID3D12CommandQueue* g_render_queue = nullptr;
bool g_render_queue_exact = false;

struct FrameContext {
    ID3D12CommandAllocator* allocator = nullptr;
    ID3D12Resource* render_target = nullptr;
    D3D12_CPU_DESCRIPTOR_HANDLE rtv{};
    UINT64 fence_value = 0;
};

struct OverlayState {
    IDXGISwapChain3* swap_chain = nullptr;
    ID3D12Device* device = nullptr;
    ID3D12CommandQueue* queue = nullptr;
    ID3D12DescriptorHeap* rtv_heap = nullptr;
    ID3D12DescriptorHeap* srv_heap = nullptr;
    ID3D12GraphicsCommandList* command_list = nullptr;
    ID3D12Fence* fence = nullptr;
    HANDLE fence_event = nullptr;
    UINT64 next_fence_value = 0;
    UINT rtv_stride = 0;
    DXGI_FORMAT format = DXGI_FORMAT_UNKNOWN;
    HWND window = nullptr;
    RECT saved_cursor_clip{};
    bool cursor_clip_saved = false;
    std::vector<FrameContext> frames;
    std::array<bool, 32> srv_descriptors{};
    UINT srv_stride = 0;
    bool imgui_context = false;
    bool win32_backend = false;
    bool dx12_backend = false;
};

std::mutex g_overlay_mutex;
OverlayState g_overlay;
thread_local bool g_inside_present = false;

template <typename T>
void SafeRelease(T*& object) {
    if (object != nullptr) {
        object->Release();
        object = nullptr;
    }
}

void OverlayLog(const char* format, ...) {
    char buffer[1024]{};
    va_list arguments;
    va_start(arguments, format);
    std::vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    if (const auto callback = g_log_callback.load(std::memory_order_relaxed)) {
        callback(buffer);
    } else {
        OutputDebugStringA(buffer);
        OutputDebugStringA("\r\n");
    }
}

BOOL WINAPI HookSetCursorPos(int x, int y) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    if (g_panel_open.load() && !g_stopping.load()) return TRUE;
    return g_set_cursor_pos_hook.unsafe_stdcall<BOOL>(x, y);
}

BOOL WINAPI HookClipCursor(const RECT* rectangle) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    return g_clip_cursor_hook.unsafe_stdcall<BOOL>(
        g_panel_open.load() && !g_stopping.load() ? nullptr : rectangle);
}

LRESULT CALLBACK OverlayWndProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    if (!g_stopping.load()) {
        if ((message == WM_KEYUP || message == WM_KEYDOWN) && wparam == VK_INSERT) {
            return 0;
        }
        if (message == WM_KILLFOCUS) g_panel_open.store(false);
        const bool keyboard = message >= WM_KEYFIRST && message <= WM_KEYLAST;
        const bool mouse = message >= WM_MOUSEFIRST && message <= WM_MOUSELAST;
        if ((keyboard || mouse || message == WM_SETFOCUS || message == WM_KILLFOCUS) &&
            g_panel_open.load()) {
            std::lock_guard lock(g_window_messages_mutex);
            if (g_window_messages.size() < 1024U)
                g_window_messages.push_back({window, message, wparam, lparam});
        }
        if (g_panel_open.load() && (keyboard || mouse || message == WM_INPUT)) {
            return message == WM_INPUT ? DefWindowProcW(window, message, wparam, lparam) : 0;
        }
    }
    const auto previous = g_original_wndproc.load();
    return previous ? CallWindowProcW(previous, window, message, wparam, lparam)
                    : DefWindowProcW(window, message, wparam, lparam);
}

void CaptureRenderQueue(ID3D12CommandQueue* queue, bool exact) {
    if (queue == nullptr || queue->GetDesc().Type != D3D12_COMMAND_LIST_TYPE_DIRECT) {
        return;
    }
    std::lock_guard lock(g_queue_mutex);
    if (g_render_queue == queue) {
        g_render_queue_exact = g_render_queue_exact || exact;
        return;
    }
    if (g_render_queue != nullptr && (g_render_queue_exact || !exact)) {
        return;
    }
    queue->AddRef();
    auto* previous = g_render_queue;
    g_render_queue = queue;
    g_render_queue_exact = exact;
    SafeRelease(previous);
    OverlayLog("[OVERLAY] d3d12-command-queue=%p source=%s", queue,
               exact ? "swap-chain" : "execute");
}

void CaptureRenderQueue(IUnknown* object, bool exact) {
    if (object == nullptr) {
        return;
    }
    ID3D12CommandQueue* queue = nullptr;
    if (SUCCEEDED(object->QueryInterface(IID_PPV_ARGS(&queue)))) {
        CaptureRenderQueue(queue, exact);
        queue->Release();
    }
}

ID3D12CommandQueue* AcquireRenderQueue() {
    std::lock_guard lock(g_queue_mutex);
    if (g_render_queue != nullptr) {
        g_render_queue->AddRef();
    }
    return g_render_queue;
}

void AllocateSrvDescriptor(ImGui_ImplDX12_InitInfo* info,
                           D3D12_CPU_DESCRIPTOR_HANDLE* cpu,
                           D3D12_GPU_DESCRIPTOR_HANDLE* gpu) {
    auto* state = static_cast<OverlayState*>(info->UserData);
    if (state == nullptr || state->srv_heap == nullptr || cpu == nullptr ||
        gpu == nullptr) {
        return;
    }
    for (std::size_t index = 0; index < state->srv_descriptors.size(); ++index) {
        if (state->srv_descriptors[index]) {
            continue;
        }
        state->srv_descriptors[index] = true;
        *cpu = state->srv_heap->GetCPUDescriptorHandleForHeapStart();
        *gpu = state->srv_heap->GetGPUDescriptorHandleForHeapStart();
        cpu->ptr += index * state->srv_stride;
        gpu->ptr += index * state->srv_stride;
        return;
    }
    cpu->ptr = 0;
    gpu->ptr = 0;
    OverlayLog("[OVERLAY] status=srv-descriptor-exhausted");
}

void FreeSrvDescriptor(ImGui_ImplDX12_InitInfo* info,
                       D3D12_CPU_DESCRIPTOR_HANDLE cpu,
                       D3D12_GPU_DESCRIPTOR_HANDLE) {
    auto* state = static_cast<OverlayState*>(info->UserData);
    if (state == nullptr || state->srv_heap == nullptr || cpu.ptr == 0U ||
        state->srv_stride == 0U) {
        return;
    }
    const auto start = state->srv_heap->GetCPUDescriptorHandleForHeapStart();
    if (cpu.ptr < start.ptr) {
        return;
    }
    const auto index = static_cast<std::size_t>(
        (cpu.ptr - start.ptr) / state->srv_stride);
    if (index < state->srv_descriptors.size()) {
        state->srv_descriptors[index] = false;
    }
}

bool WaitForFrame(FrameContext& frame, DWORD timeout_ms) {
    if (frame.fence_value == 0U || g_overlay.fence == nullptr ||
        g_overlay.fence->GetCompletedValue() >= frame.fence_value) {
        return true;
    }
    if (FAILED(g_overlay.fence->SetEventOnCompletion(frame.fence_value,
                                                      g_overlay.fence_event))) {
        return false;
    }
    return WaitForSingleObject(g_overlay.fence_event, timeout_ms) == WAIT_OBJECT_0;
}

void ShutdownOverlay() {
    g_panel_open.store(false);
    if (g_overlay.cursor_clip_saved) {
        ClipCursor(&g_overlay.saved_cursor_clip);
        g_overlay.cursor_clip_saved = false;
    }
    if (g_overlay.window && IsWindow(g_overlay.window) && g_original_wndproc.load()) {
        const auto current = reinterpret_cast<WNDPROC>(GetWindowLongPtrW(g_overlay.window, GWLP_WNDPROC));
        if (current == &OverlayWndProc) {
            SetLastError(0);
            if (!SetWindowLongPtrW(g_overlay.window, GWLP_WNDPROC,
                    reinterpret_cast<LONG_PTR>(g_original_wndproc.load())) && GetLastError())
                g_window_chain_unsafe.store(true);
        } else if (current != g_original_wndproc.load()) {
            g_window_chain_unsafe.store(true);
        }
    }
    {
        std::lock_guard lock(g_window_messages_mutex);
        g_window_messages.clear();
    }
    if (g_overlay.fence != nullptr && g_overlay.fence_event != nullptr) {
        for (auto& frame : g_overlay.frames) {
            WaitForFrame(frame, 2000U);
        }
    }
    if (g_overlay.dx12_backend) {
        ImGui_ImplDX12_Shutdown();
        g_overlay.dx12_backend = false;
    }
    if (g_overlay.win32_backend) {
        ImGui_ImplWin32_Shutdown();
        g_overlay.win32_backend = false;
    }
    if (g_overlay.imgui_context) {
        ImGui::DestroyContext();
        g_overlay.imgui_context = false;
    }
    for (auto& frame : g_overlay.frames) {
        SafeRelease(frame.render_target);
        SafeRelease(frame.allocator);
    }
    g_overlay.frames.clear();
    SafeRelease(g_overlay.command_list);
    SafeRelease(g_overlay.fence);
    SafeRelease(g_overlay.srv_heap);
    SafeRelease(g_overlay.rtv_heap);
    SafeRelease(g_overlay.queue);
    SafeRelease(g_overlay.device);
    SafeRelease(g_overlay.swap_chain);
    if (g_overlay.fence_event != nullptr) {
        CloseHandle(g_overlay.fence_event);
        g_overlay.fence_event = nullptr;
    }
    g_overlay.next_fence_value = 0U;
    g_overlay.rtv_stride = 0U;
    g_overlay.srv_stride = 0U;
    g_overlay.format = DXGI_FORMAT_UNKNOWN;
    g_overlay.window = nullptr;
    g_overlay.srv_descriptors.fill(false);
}

bool SameDevice(ID3D12Device* first, ID3D12Device* second) {
    if (first == nullptr || second == nullptr) {
        return false;
    }
    IUnknown* first_identity = nullptr;
    IUnknown* second_identity = nullptr;
    first->QueryInterface(IID_PPV_ARGS(&first_identity));
    second->QueryInterface(IID_PPV_ARGS(&second_identity));
    const bool same = first_identity != nullptr && first_identity == second_identity;
    SafeRelease(first_identity);
    SafeRelease(second_identity);
    return same;
}

bool InitializeOverlay(IDXGISwapChain* incoming_swap_chain) {
    ShutdownOverlay();

    IDXGISwapChain3* swap_chain = nullptr;
    ID3D12Device* device = nullptr;
    ID3D12CommandQueue* queue = AcquireRenderQueue();
    ID3D12Device* queue_device = nullptr;
    DXGI_SWAP_CHAIN_DESC swap_desc{};
    if (incoming_swap_chain == nullptr || queue == nullptr ||
        FAILED(incoming_swap_chain->QueryInterface(IID_PPV_ARGS(&swap_chain))) ||
        FAILED(swap_chain->GetDevice(IID_PPV_ARGS(&device))) ||
        FAILED(queue->GetDevice(IID_PPV_ARGS(&queue_device))) ||
        !SameDevice(device, queue_device) || FAILED(swap_chain->GetDesc(&swap_desc)) ||
        swap_desc.BufferCount == 0U || swap_desc.OutputWindow == nullptr) {
        SafeRelease(queue_device);
        SafeRelease(queue);
        SafeRelease(device);
        SafeRelease(swap_chain);
        return false;
    }
    SafeRelease(queue_device);

    g_overlay.swap_chain = swap_chain;
    g_overlay.device = device;
    g_overlay.queue = queue;
    g_overlay.window = swap_desc.OutputWindow;
    g_overlay.format = swap_desc.BufferDesc.Format;
    g_overlay.frames.resize(swap_desc.BufferCount);

    D3D12_DESCRIPTOR_HEAP_DESC rtv_desc{};
    rtv_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    rtv_desc.NumDescriptors = swap_desc.BufferCount;
    if (FAILED(device->CreateDescriptorHeap(
            &rtv_desc, IID_PPV_ARGS(&g_overlay.rtv_heap)))) {
        ShutdownOverlay();
        return false;
    }
    D3D12_DESCRIPTOR_HEAP_DESC srv_desc{};
    srv_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    srv_desc.NumDescriptors = static_cast<UINT>(g_overlay.srv_descriptors.size());
    srv_desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
    if (FAILED(device->CreateDescriptorHeap(
            &srv_desc, IID_PPV_ARGS(&g_overlay.srv_heap)))) {
        ShutdownOverlay();
        return false;
    }
    g_overlay.rtv_stride = device->GetDescriptorHandleIncrementSize(
        D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
    g_overlay.srv_stride = device->GetDescriptorHandleIncrementSize(
        D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    auto rtv = g_overlay.rtv_heap->GetCPUDescriptorHandleForHeapStart();
    for (UINT index = 0U; index < swap_desc.BufferCount; ++index) {
        auto& frame = g_overlay.frames[index];
        frame.rtv = rtv;
        if (FAILED(device->CreateCommandAllocator(
                D3D12_COMMAND_LIST_TYPE_DIRECT,
                IID_PPV_ARGS(&frame.allocator))) ||
            FAILED(swap_chain->GetBuffer(
                index, IID_PPV_ARGS(&frame.render_target)))) {
            ShutdownOverlay();
            return false;
        }
        device->CreateRenderTargetView(frame.render_target, nullptr, frame.rtv);
        rtv.ptr += g_overlay.rtv_stride;
    }
    if (FAILED(device->CreateCommandList(
            0U, D3D12_COMMAND_LIST_TYPE_DIRECT,
            g_overlay.frames.front().allocator, nullptr,
            IID_PPV_ARGS(&g_overlay.command_list))) ||
        FAILED(g_overlay.command_list->Close()) ||
        FAILED(device->CreateFence(
            0U, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&g_overlay.fence)))) {
        ShutdownOverlay();
        return false;
    }
    g_overlay.fence_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (g_overlay.fence_event == nullptr) {
        ShutdownOverlay();
        return false;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    g_overlay.imgui_context = true;
    auto& io = ImGui::GetIO();
    io.Fonts->AddFontDefault();
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 5.0F;
    style.FrameRounding = 3.0F;
    if (!ImGui_ImplWin32_Init(g_overlay.window)) {
        ShutdownOverlay();
        return false;
    }
    g_overlay.win32_backend = true;
    ImGui_ImplDX12_InitInfo init_info{};
    init_info.Device = device;
    init_info.CommandQueue = queue;
    init_info.NumFramesInFlight = static_cast<int>(swap_desc.BufferCount);
    init_info.RTVFormat = g_overlay.format;
    init_info.DSVFormat = DXGI_FORMAT_UNKNOWN;
    init_info.UserData = &g_overlay;
    init_info.SrvDescriptorHeap = g_overlay.srv_heap;
    init_info.SrvDescriptorAllocFn = &AllocateSrvDescriptor;
    init_info.SrvDescriptorFreeFn = &FreeSrvDescriptor;
    if (!ImGui_ImplDX12_Init(&init_info)) {
        ShutdownOverlay();
        return false;
    }
    g_overlay.dx12_backend = true;
    g_original_wndproc.store(reinterpret_cast<WNDPROC>(
        GetWindowLongPtrW(g_overlay.window, GWLP_WNDPROC)));
    SetLastError(ERROR_SUCCESS);
    const auto previous = SetWindowLongPtrW(
        g_overlay.window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&OverlayWndProc));
    if (previous == 0 && GetLastError() != ERROR_SUCCESS) {
        OverlayLog("[OVERLAY] status=wndproc-hook-failed error=%lu", GetLastError());
        ShutdownOverlay();
        return false;
    }
    OverlayLog("[OVERLAY] status=ready backend=dx12 hwnd=%p buffers=%u format=%u",
               g_overlay.window, swap_desc.BufferCount,
               static_cast<unsigned>(g_overlay.format));
    return true;
}

bool RenderOverlay(IDXGISwapChain* swap_chain) {
    if (g_overlay.swap_chain != swap_chain && !InitializeOverlay(swap_chain)) {
        static std::atomic<bool> logged{};
        if (!logged.exchange(true, std::memory_order_relaxed)) {
            OverlayLog("[OVERLAY] status=waiting-for-compatible-swap-chain");
        }
        return false;
    }
    // Raw keyboard registration can suppress legacy WM_KEYUP messages.
    static bool insert_was_down = false;
    const bool focused = GetForegroundWindow() == g_overlay.window;
    const bool insert_down = focused && (GetAsyncKeyState(VK_INSERT) & 0x8000) != 0;
    if (insert_down && !insert_was_down) g_panel_open.store(!g_panel_open.load());
    insert_was_down = insert_down;
    if (!focused) g_panel_open.store(false);
    const UINT index = g_overlay.swap_chain->GetCurrentBackBufferIndex();
    if (index >= g_overlay.frames.size()) {
        return false;
    }
    auto& frame = g_overlay.frames[index];
    if (!WaitForFrame(frame, 1000U) || FAILED(frame.allocator->Reset()) ||
        FAILED(g_overlay.command_list->Reset(frame.allocator, nullptr))) {
        OverlayLog("[OVERLAY] status=frame-reset-failed index=%u", index);
        return false;
    }

    ImGui_ImplDX12_NewFrame();
    ImGui_ImplWin32_NewFrame();
    std::vector<WindowMessage> messages;
    {
        std::lock_guard lock(g_window_messages_mutex);
        messages.swap(g_window_messages);
    }
    const bool panel_open = g_panel_open.load();
    static bool previous_panel_open = false;
    if (panel_open != previous_panel_open) {
        ImGui::GetIO().ClearInputKeys();
        if (panel_open) {
            g_overlay.cursor_clip_saved = GetClipCursor(&g_overlay.saved_cursor_clip) != FALSE;
        } else if (g_overlay.cursor_clip_saved) {
            ClipCursor(&g_overlay.saved_cursor_clip);
            g_overlay.cursor_clip_saved = false;
        }
        previous_panel_open = panel_open;
        OverlayLog("[OVERLAY] panel=%s", panel_open ? "open" : "closed");
    }
    for (const auto& message : messages)
        ImGui_ImplWin32_WndProcHandler(message.window, message.message,
                                      message.wparam, message.lparam);
    ImGui::GetIO().MouseDrawCursor = panel_open;
    if (panel_open) ClipCursor(nullptr);
    ImGui::NewFrame();
    if (panel_open) {
        ImGui::SetNextWindowPos(ImVec2(18.0F, 18.0F), ImGuiCond_FirstUseEver);
    } else {
        ImGui::SetNextWindowPos(ImVec2(18.0F, 18.0F), ImGuiCond_Always);
    }
    ImGui::SetNextWindowBgAlpha(0.62F);
    constexpr ImGuiWindowFlags kPanelFlags =
        ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings;
    constexpr ImGuiWindowFlags kHudFlags =
        kPanelFlags | ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoInputs;
    ImGui::Begin(panel_open ? "RoE Trace" : "roe_trace coordinates", nullptr,
                 panel_open ? kPanelFlags : kHudFlags);
    ImGui::TextUnformatted("POS");
    ImGui::Separator();
    if (g_coordinate_valid.load(std::memory_order_acquire)) {
        ImGui::Text("X  %.3f", g_coordinate_x.load(std::memory_order_relaxed));
        ImGui::Text("Y  %.3f", g_coordinate_y.load(std::memory_order_relaxed));
        ImGui::Text("Z  %.3f", g_coordinate_z.load(std::memory_order_relaxed));
    } else {
        ImGui::TextDisabled("Waiting for local Actor...");
    }
    ImGui::TextDisabled(panel_open ? "Insert: close panel" : "Insert: open panel");
    ImGui::End();
    ImGui::Render();

    D3D12_RESOURCE_BARRIER barrier{};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = frame.render_target;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
    g_overlay.command_list->ResourceBarrier(1U, &barrier);
    g_overlay.command_list->OMSetRenderTargets(1U, &frame.rtv, FALSE, nullptr);
    ID3D12DescriptorHeap* heaps[]{g_overlay.srv_heap};
    g_overlay.command_list->SetDescriptorHeaps(1U, heaps);
    ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), g_overlay.command_list);
    std::swap(barrier.Transition.StateBefore, barrier.Transition.StateAfter);
    g_overlay.command_list->ResourceBarrier(1U, &barrier);
    if (FAILED(g_overlay.command_list->Close())) {
        return false;
    }
    ID3D12CommandList* lists[]{g_overlay.command_list};
    g_overlay.queue->ExecuteCommandLists(1U, lists);
    const UINT64 fence_value = ++g_overlay.next_fence_value;
    if (FAILED(g_overlay.queue->Signal(g_overlay.fence, fence_value))) {
        return false;
    }
    frame.fence_value = fence_value;
    return true;
}

HRESULT STDMETHODCALLTYPE HookPresent(IDXGISwapChain* swap_chain,
                                      UINT sync_interval, UINT flags) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    static std::atomic<bool> logged{};
    if (!logged.exchange(true, std::memory_order_relaxed)) {
        OverlayLog("[OVERLAY] present-path=Present swap-chain=%p", swap_chain);
    }
    const bool outer_present = !g_inside_present;
    g_inside_present = true;
    if (outer_present && !g_stopping.load(std::memory_order_relaxed) &&
        (flags & DXGI_PRESENT_TEST) == 0U) {
        std::lock_guard lock(g_overlay_mutex);
        RenderOverlay(swap_chain);
    }
    const auto result = g_present_hook.unsafe_stdcall<HRESULT>(
        swap_chain, sync_interval, flags);
    if (outer_present) {
        g_inside_present = false;
    }
    return result;
}

HRESULT STDMETHODCALLTYPE HookPresent1(IDXGISwapChain1* swap_chain,
    UINT sync_interval, UINT flags,
    const DXGI_PRESENT_PARAMETERS* parameters) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    static std::atomic<bool> logged{};
    if (!logged.exchange(true, std::memory_order_relaxed)) {
        OverlayLog("[OVERLAY] present-path=Present1 swap-chain=%p", swap_chain);
    }
    const bool outer_present = !g_inside_present;
    g_inside_present = true;
    if (outer_present && !g_stopping.load(std::memory_order_relaxed) &&
        (flags & DXGI_PRESENT_TEST) == 0U) {
        std::lock_guard lock(g_overlay_mutex);
        RenderOverlay(swap_chain);
    }
    const auto result = g_present1_hook.unsafe_stdcall<HRESULT>(
        swap_chain, sync_interval, flags, parameters);
    if (outer_present) {
        g_inside_present = false;
    }
    return result;
}

HRESULT STDMETHODCALLTYPE HookResizeBuffers(IDXGISwapChain* swap_chain,
    UINT buffer_count, UINT width, UINT height, DXGI_FORMAT format,
    UINT flags) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    {
        std::lock_guard lock(g_overlay_mutex);
        if (g_overlay.swap_chain == swap_chain) {
            ShutdownOverlay();
            OverlayLog("[OVERLAY] status=resize width=%u height=%u", width,
                       height);
        }
    }
    return g_resize_buffers_hook.unsafe_stdcall<HRESULT>(
        swap_chain, buffer_count, width, height, format, flags);
}

HRESULT STDMETHODCALLTYPE HookResizeBuffers1(IDXGISwapChain3* swap_chain,
    UINT buffer_count, UINT width, UINT height, DXGI_FORMAT format,
    UINT flags, const UINT* creation_node_mask,
    IUnknown* const* present_queues) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    {
        std::lock_guard lock(g_overlay_mutex);
        if (g_overlay.swap_chain == swap_chain) {
            ShutdownOverlay();
            OverlayLog("[OVERLAY] status=resize1 width=%u height=%u", width,
                       height);
        }
    }
    if (present_queues != nullptr && buffer_count != 0U) {
        CaptureRenderQueue(present_queues[0], true);
    }
    return g_resize_buffers1_hook.unsafe_stdcall<HRESULT>(
        swap_chain, buffer_count, width, height, format, flags,
        creation_node_mask, present_queues);
}

void STDMETHODCALLTYPE HookExecuteCommandLists(ID3D12CommandQueue* queue,
    UINT count, ID3D12CommandList* const* lists) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    CaptureRenderQueue(queue, false);
    g_execute_command_lists_hook.unsafe_stdcall<void>(queue, count, lists);
}

HRESULT STDMETHODCALLTYPE HookCreateSwapChain(IDXGIFactory* factory,
    IUnknown* device, DXGI_SWAP_CHAIN_DESC* desc, IDXGISwapChain** swap_chain) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto result = g_create_swap_chain_hook.unsafe_stdcall<HRESULT>(
        factory, device, desc, swap_chain);
    if (SUCCEEDED(result)) {
        CaptureRenderQueue(device, true);
    }
    return result;
}

HRESULT STDMETHODCALLTYPE HookCreateSwapChainForHwnd(IDXGIFactory2* factory,
    IUnknown* device, HWND window, const DXGI_SWAP_CHAIN_DESC1* desc,
    const DXGI_SWAP_CHAIN_FULLSCREEN_DESC* fullscreen_desc, IDXGIOutput* output,
    IDXGISwapChain1** swap_chain) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto result =
        g_create_swap_chain_for_hwnd_hook.unsafe_stdcall<HRESULT>(
            factory, device, window, desc, fullscreen_desc, output, swap_chain);
    if (SUCCEEDED(result)) {
        CaptureRenderQueue(device, true);
    }
    return result;
}

template <typename Function>
bool InstallHook(const char* name, void* target, Function detour,
                 safetyhook::InlineHook& hook) {
    auto result = safetyhook::InlineHook::create(target, detour);
    if (!result) {
        OverlayLog("[OVERLAY-HOOK] name=%s status=failed target=%p error=%u",
                   name, target, static_cast<unsigned>(result.error().type));
        return false;
    }
    hook = std::move(*result);
    OverlayLog("[OVERLAY-HOOK] name=%s status=installed target=%p", name,
               target);
    return true;
}

} // namespace

void SetLogCallback(LogCallback callback) {
    g_log_callback.store(callback, std::memory_order_relaxed);
}

bool InstallD3D12Hooks() {
    const auto user32 = GetModuleHandleW(L"user32.dll");
    if (user32 != nullptr) {
        if (!g_set_cursor_pos_hook)
            InstallHook("SetCursorPos", reinterpret_cast<void*>(GetProcAddress(user32, "SetCursorPos")),
                        &HookSetCursorPos, g_set_cursor_pos_hook);
        if (!g_clip_cursor_hook)
            InstallHook("ClipCursor", reinterpret_cast<void*>(GetProcAddress(user32, "ClipCursor")),
                        &HookClipCursor, g_clip_cursor_hook);
    }
    if (g_present_hook && g_present1_hook && g_resize_buffers_hook &&
        g_resize_buffers1_hook &&
        g_execute_command_lists_hook && g_create_swap_chain_hook &&
        g_create_swap_chain_for_hwnd_hook) {
        return true;
    }

    wchar_t class_name[96]{};
    std::swprintf(class_name, std::size(class_name),
                  L"roe_trace_dx12_probe_%lu", GetCurrentProcessId());
    const HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_CLASSDC;
    window_class.lpfnWndProc = DefWindowProcW;
    window_class.hInstance = instance;
    window_class.lpszClassName = class_name;
    if (RegisterClassExW(&window_class) == 0U) {
        OverlayLog("[OVERLAY-HOOK] status=window-class-failed error=%lu",
                   GetLastError());
        return false;
    }
    const HWND window = CreateWindowExW(
        0U, class_name, L"roe_trace dx12 probe", WS_OVERLAPPEDWINDOW,
        0, 0, 100, 100, nullptr, nullptr, instance, nullptr);
    if (window == nullptr) {
        UnregisterClassW(class_name, instance);
        OverlayLog("[OVERLAY-HOOK] status=window-failed error=%lu",
                   GetLastError());
        return false;
    }

    IDXGIFactory4* factory = nullptr;
    ID3D12Device* device = nullptr;
    ID3D12CommandQueue* queue = nullptr;
    IDXGISwapChain1* swap_chain1 = nullptr;
    IDXGISwapChain3* swap_chain3 = nullptr;
    bool installed = false;
    if (SUCCEEDED(CreateDXGIFactory1(IID_PPV_ARGS(&factory))) &&
        SUCCEEDED(D3D12CreateDevice(
            nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device)))) {
        D3D12_COMMAND_QUEUE_DESC queue_desc{};
        queue_desc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
        if (SUCCEEDED(device->CreateCommandQueue(
                &queue_desc, IID_PPV_ARGS(&queue)))) {
            DXGI_SWAP_CHAIN_DESC1 swap_desc{};
            swap_desc.Width = 100U;
            swap_desc.Height = 100U;
            swap_desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            swap_desc.SampleDesc.Count = 1U;
            swap_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            swap_desc.BufferCount = 2U;
            swap_desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
            if (SUCCEEDED(factory->CreateSwapChainForHwnd(
                    queue, window, &swap_desc, nullptr, nullptr,
                    &swap_chain1)) &&
                SUCCEEDED(swap_chain1->QueryInterface(
                    IID_PPV_ARGS(&swap_chain3)))) {
                auto** swap_vtable = *reinterpret_cast<void***>(swap_chain3);
                auto** queue_vtable = *reinterpret_cast<void***>(queue);
                auto** factory_vtable = *reinterpret_cast<void***>(factory);
                installed =
                    InstallHook("Present", swap_vtable[8], &HookPresent,
                                g_present_hook) &&
                    InstallHook("Present1", swap_vtable[22], &HookPresent1,
                                g_present1_hook) &&
                    InstallHook("ResizeBuffers", swap_vtable[13],
                                &HookResizeBuffers, g_resize_buffers_hook) &&
                    InstallHook("ResizeBuffers1", swap_vtable[39],
                                &HookResizeBuffers1,
                                g_resize_buffers1_hook) &&
                    InstallHook("ExecuteCommandLists", queue_vtable[10],
                                &HookExecuteCommandLists,
                                g_execute_command_lists_hook) &&
                    InstallHook("CreateSwapChain", factory_vtable[10],
                                &HookCreateSwapChain,
                                g_create_swap_chain_hook) &&
                    InstallHook("CreateSwapChainForHwnd", factory_vtable[15],
                                &HookCreateSwapChainForHwnd,
                                g_create_swap_chain_for_hwnd_hook);
            }
        }
    }
    SafeRelease(swap_chain3);
    SafeRelease(swap_chain1);
    SafeRelease(queue);
    SafeRelease(device);
    SafeRelease(factory);
    DestroyWindow(window);
    UnregisterClassW(class_name, instance);
    OverlayLog("[OVERLAY-HOOK] status=%s backend=dx12",
               installed ? "ready" : "failed");
    return installed;
}

void UpdateCoordinates(double x, double y, double z) {
    g_coordinate_x.store(x, std::memory_order_relaxed);
    g_coordinate_y.store(y, std::memory_order_relaxed);
    g_coordinate_z.store(z, std::memory_order_relaxed);
    g_coordinate_valid.store(true, std::memory_order_release);
}

void Stop() {
    g_stopping.store(true, std::memory_order_relaxed);
    g_panel_open.store(false);
}

namespace {
auto OverlayHooks() {
    return std::array<safetyhook::InlineHook*, 9>{&g_present_hook, &g_present1_hook,
        &g_resize_buffers_hook, &g_resize_buffers1_hook, &g_execute_command_lists_hook,
        &g_create_swap_chain_hook, &g_create_swap_chain_for_hwnd_hook,
        &g_set_cursor_pos_hook, &g_clip_cursor_hook};
}
}

bool DisableHooksForUnload() {
    Stop();
    bool success = !g_window_chain_unsafe.load();
    for (auto* hook : OverlayHooks())
        if (*hook && !hook->disable()) success = false;
    HWND window = nullptr;
    {
        std::lock_guard lock(g_overlay_mutex);
        window = g_overlay.window;
        const auto previous = g_original_wndproc.load();
        if (window && IsWindow(window) && previous) {
            const auto current = reinterpret_cast<WNDPROC>(GetWindowLongPtrW(window, GWLP_WNDPROC));
            if (current == &OverlayWndProc) {
                SetLastError(0);
                if (!SetWindowLongPtrW(window, GWLP_WNDPROC,
                        reinterpret_cast<LONG_PTR>(previous)) && GetLastError()) success = false;
            } else if (current != previous) {
                // A later subclass may still chain to our DLL. Do not strand it.
                success = false;
            }
        }
    }
    if (window && IsWindow(window)) {
        DWORD_PTR ignored = 0;
        if (!SendMessageTimeoutW(window, WM_NULL, 0, 0,
                SMTO_ABORTIFHUNG | SMTO_BLOCK, 2000U, &ignored)) success = false;
    }
    return success;
}

void AppendHookCodeRanges(std::vector<trace_lifecycle::CodeRange>& ranges) {
    for (auto* hook : OverlayHooks())
        if (*hook) ranges.push_back({hook->trampoline().address(), hook->trampoline().size()});
}

bool FinishShutdown() {
    std::lock_guard lock(g_overlay_mutex);
    // Unlike resize's historical path, unloading must not release GPU-owned
    // resources when the fence times out. Retain the DLL/resources and retry.
    for (auto& frame : g_overlay.frames)
        if (!WaitForFrame(frame, 2000U)) return false;
    ShutdownOverlay();
    {
        std::lock_guard queue_lock(g_queue_mutex);
        SafeRelease(g_render_queue);
        g_render_queue_exact = false;
    }
    return true;
}

} // namespace roe::trace_overlay
