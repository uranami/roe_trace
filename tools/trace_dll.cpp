#if !defined(_WIN32)
#error "roe_trace is a Windows-only diagnostic DLL"
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>

#include <safetyhook.hpp>

#include "message_names.hpp"
#include "trace_overlay.hpp"
#include "trace_remote_probe.hpp"
#ifdef _MSC_VER
#include <intrin.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace {

using ConnectFn = int(WSAAPI*)(SOCKET, const sockaddr*, int);
using SendToFn = int(WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
using RecvFromFn = int(WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);

// Prototypes recovered from Europa_Client_tp6_unpacked.exe with Hex-Rays.
using InternalSendFn = char(__fastcall*)(std::int64_t, unsigned int, const void*, int, unsigned int);
using DecodedRecordFn = std::int64_t(__fastcall*)(std::int64_t, std::uint8_t*, std::int64_t,
                                                   char*, int, int*);
using MessageDispatchFn = std::int64_t(__fastcall*)(
    std::int64_t, unsigned int, std::int64_t, unsigned int);
using ReqJoinInstanceFn = std::int64_t(__fastcall*)(std::int64_t);
using InstanceNotifyFn = void(__fastcall*)(std::int64_t);
using JoinInstanceRspFn = void(__fastcall*)(std::int64_t);
using StartPointTickFn = std::int64_t(__fastcall*)(std::int64_t);
using StartPointEventFn = std::int64_t(__fastcall*)(
    std::int64_t, std::uint8_t*, std::int64_t**);
using MapMouseCallbackFn = std::int64_t(__fastcall*)(std::int64_t, std::int64_t*);
using MovementActorLookupFn = std::int64_t(__fastcall*)(std::uint64_t);
using ActorSetPositionFn = std::int64_t(__fastcall*)(std::uintptr_t,
                                                     const float*);
using PresentationSetActiveFn = std::int64_t(__fastcall*)(std::uintptr_t,
                                                           std::uint8_t);
using MovementPhysicsTickFn = void(__fastcall*)(float*, float);
using PresentationEventFn = char(__fastcall*)(std::uintptr_t, unsigned int);
using MovementStateActionFn = void(__fastcall*)(std::uintptr_t, int, int,
                                                 std::uintptr_t);
using GroundMovementUpdateFn = std::uint8_t(__fastcall*)(
    std::uintptr_t, const std::uint8_t*, std::uintptr_t, float,
    std::uint8_t, std::uint8_t, std::uintptr_t);
using AirMovementUpdateFn = std::uint8_t(__fastcall*)(
    std::uintptr_t, const std::uint8_t*, std::uintptr_t, float, int,
    std::uint8_t, std::uintptr_t);
using ActorRecalculateGroundSpeedsFn = std::int64_t(__fastcall*)(
    std::uintptr_t);
using ActorResourceLookupFn = std::uintptr_t(__fastcall*)(unsigned int,
                                                           std::uint64_t);
using MovementSpeedLimitsFn = float*(__fastcall*)(
    std::uintptr_t, std::uintptr_t, unsigned int, unsigned int, std::uint8_t,
    std::uint8_t, float*, float*, float*);
using FallingMovementUpdateFn = std::uint8_t(__fastcall*)(
    std::uintptr_t, const std::uint8_t*, std::uintptr_t, float, int,
    std::uint8_t, std::uintptr_t);
using RelayStopSessionFn = std::uint8_t(__fastcall*)(std::uintptr_t);
using RelayStateChangedFn = std::uintptr_t(__fastcall*)(
    std::uintptr_t, std::uintptr_t, int, std::uintptr_t);
using ForceReconnectFn = std::int64_t(__fastcall*)(std::uintptr_t, int);
using GCloudReconnectFn = std::int64_t(__fastcall*)(std::uintptr_t,
                                                     unsigned int);
using RoomListRefreshFn = void(__fastcall*)(std::uintptr_t,
                                            const std::uint32_t*);
using RoomPageSelectFn = std::int64_t(__fastcall*)();
using RoomPageRefreshFn = std::int64_t(__fastcall*)(std::uintptr_t);
using SelectedRoleSetterFn = std::int64_t(__fastcall*)(std::uint64_t);

safetyhook::InlineHook g_connect_hook{};
safetyhook::InlineHook g_sendto_hook{};
safetyhook::InlineHook g_recvfrom_hook{};
safetyhook::InlineHook g_internal_send_hook{};
safetyhook::InlineHook g_decoded_record_hook{};
safetyhook::InlineHook g_message_dispatch_hook{};
safetyhook::InlineHook g_req_join_instance_hook{};
safetyhook::InlineHook g_instance_notify_hook{};
safetyhook::InlineHook g_join_instance_rsp_hook{};
safetyhook::InlineHook g_startpoint_tick_hook{};
safetyhook::InlineHook g_startpoint_event_hook{};
safetyhook::InlineHook g_map_mouse_click_hook{};
safetyhook::InlineHook g_map_mouse_move_hook{};
safetyhook::InlineHook g_actor_set_position_hook{};
safetyhook::InlineHook g_movement_physics_tick_hook{};
#ifdef ROE_TRACE_LIFECYCLE_TEST_BUILD
safetyhook::MidHook g_lifecycle_test_mid_hook{};
#endif
safetyhook::InlineHook g_presentation_event_hook{};
safetyhook::InlineHook g_movement_state_action_hook{};
safetyhook::InlineHook g_ground_movement_update_hook{};
safetyhook::InlineHook g_air_movement_update_hook{};
safetyhook::InlineHook g_movement_speed_limits_hook{};
safetyhook::InlineHook g_falling_movement_update_hook{};
safetyhook::InlineHook g_relay_stop_session_hook{};
safetyhook::InlineHook g_relay_state_changed_hook{};
safetyhook::InlineHook g_force_reconnect_hook{};
safetyhook::InlineHook g_gcloud_reconnect_hook{};
safetyhook::InlineHook g_room_list_refresh_hook{};
safetyhook::InlineHook g_room_page_select_hook{};
safetyhook::InlineHook g_room_page_refresh_hook{};
safetyhook::InlineHook g_selected_role_setter_hook{};

HANDLE g_log_file = INVALID_HANDLE_VALUE;
HANDLE g_console_output = INVALID_HANDLE_VALUE;
HANDLE g_log_writer_thread = nullptr;
HANDLE g_unload_event = nullptr;
bool g_owned_console = false;
std::atomic<bool> g_log_stopping{};
std::mutex g_log_queue_mutex;
std::condition_variable g_log_queue_ready;
std::deque<std::string> g_log_queue;
std::atomic<std::uint32_t> g_dropped_log_lines{};
std::atomic<bool> g_log_writer_started{};
std::array<std::atomic<std::uint32_t>, 65536> g_outgoing_counts{};
std::array<std::atomic<std::uint32_t>, 65536> g_incoming_counts{};
std::atomic<std::uint32_t> g_udp_events{};
std::atomic<bool> g_udp_stack_logged{};
std::atomic<bool> g_enter_room_record_dumped{};
std::atomic<bool> g_message_names_dumped{};
std::atomic<bool> g_movement_handlers_dumped{};
std::atomic<bool> g_room_handlers_dumped{};
std::atomic<std::uintptr_t> g_main_module_base{};
std::atomic<std::uintptr_t> g_last_message_dispatcher{};
std::atomic<std::uint64_t> g_login_world_actor_rid{};
std::atomic<bool> g_selected_role_compat_attempted{};
std::atomic<std::uint64_t> g_scene_actor_id{};
std::atomic<std::uintptr_t> g_scene_actor_pointer{};
std::atomic<bool> g_movement_actor_signature_failed{};
std::atomic<std::uint32_t> g_actor_transform_calls{};
std::atomic<std::uintptr_t> g_last_presentation_child{};
std::mutex g_remote_probe_mutex;
roe::trace_remote::Registry<> g_remote_probes;
roe::trace_remote::Registry<> g_deployable_probes;
std::atomic<bool> g_gameplay_move_stack_logged{};
std::atomic<bool> g_presentation_compat_attempted{};
std::atomic<std::uint32_t> g_movement_physics_ticks{};
std::atomic<std::uint32_t> g_movement_physics_burst{};
std::atomic<std::uintptr_t> g_last_movement_state{};
std::atomic<std::uint32_t> g_last_movement_state_index{0xffffffffU};
std::atomic<bool> g_ground_speed_recalc_attempted{};
std::atomic<bool> g_ground_speed_recalc_signature_failed{};
std::atomic<bool> g_speed_limits_logged{};
std::atomic<bool> g_actor_resource_lookup_signature_failed{};
volatile LONG g_stopping = 0;

bool StopRequested() {
    if (roe::trace_lifecycle::unload_requested.load() ||
        (g_unload_event && WaitForSingleObject(g_unload_event, 0) == WAIT_OBJECT_0)) {
        InterlockedExchange(&g_stopping, 1);
    }
    return InterlockedCompareExchange(&g_stopping, 0, 0) != 0;
}

constexpr std::uintptr_t kPreferredImageBase = 0x140000000ULL;
constexpr std::uintptr_t kInternalSendVa = 0x14097A300ULL;
constexpr std::uintptr_t kDecodedRecordVa = 0x14097C770ULL;
constexpr std::uintptr_t kMessageDispatchVa = 0x14097ABD0ULL;
constexpr std::uintptr_t kReqJoinInstanceVa = 0x140B34180ULL;
constexpr std::uintptr_t kInstanceNotifyVa = 0x140B342C0ULL;
constexpr std::uintptr_t kJoinInstanceRspVa = 0x140B34410ULL;
constexpr std::uintptr_t kStartPointTickVa = 0x1410428A0ULL;
constexpr std::uintptr_t kStartPointEventVa = 0x141042FB0ULL;
constexpr std::uintptr_t kMapMouseClickVa = 0x141040430ULL;
constexpr std::uintptr_t kMapMouseMoveVa = 0x141040660ULL;
constexpr std::uintptr_t kMapCursorGlobalVa = 0x1431AE4D0ULL;
constexpr std::uintptr_t kFrameClockGlobalVa = 0x1431ADE08ULL;
constexpr std::uintptr_t kBornPositionManagerGlobalVa = 0x1431C4DC8ULL;
constexpr std::uintptr_t kSceneContextGlobalVa = 0x1431C4E58ULL;
constexpr std::uintptr_t kMovementActorLookupVa = 0x140F9D250ULL;
constexpr std::uintptr_t kActorSetPositionVa = 0x140B66570ULL;
constexpr std::uintptr_t kPresentationSetActiveVa = 0x1409521B0ULL;
constexpr std::uintptr_t kMovementPhysicsTickVa = 0x140F59910ULL;
constexpr std::uintptr_t kPresentationEventVa = 0x140961AB0ULL;
constexpr std::uintptr_t kMovementStateActionVa = 0x140AEE5D0ULL;
constexpr std::uintptr_t kGroundMovementUpdateVa = 0x1411206D0ULL;
constexpr std::uintptr_t kAirMovementUpdateVa = 0x140F85020ULL;
constexpr std::uintptr_t kActorRecalculateGroundSpeedsVa = 0x140B572D0ULL;
constexpr std::uintptr_t kActorResourceLookupVa = 0x140B0EF50ULL;
constexpr std::uintptr_t kMovementSpeedLimitsVa = 0x140E62E90ULL;
constexpr std::uintptr_t kFallingMovementUpdateVa = 0x1411153B0ULL;
constexpr std::uintptr_t kRelayStopSessionVa = 0x14174E890ULL;
constexpr std::uintptr_t kRelayStateChangedVa = 0x140977F70ULL;
constexpr std::uintptr_t kForceReconnectVa = 0x140B47B10ULL;
constexpr std::uintptr_t kGCloudReconnectVa = 0x141723990ULL;
constexpr std::uintptr_t kRoomListRefreshVa = 0x141153AF0ULL;
constexpr std::uintptr_t kRoomPageSelectVa = 0x141144610ULL;
constexpr std::uintptr_t kRoomPageRefreshVa = 0x141144DF0ULL;
constexpr std::uintptr_t kSelectedRoleSetterVa = 0x140B3A3C0ULL;
constexpr std::uintptr_t kRoomStateGlobalVa = 0x1431C4F40ULL;
constexpr std::uintptr_t kLobbyActorGlobalVa = 0x1431C4F58ULL;
constexpr std::uintptr_t kRoomUiReadyVa = 0x1431ADC69ULL;
constexpr std::size_t kDefaultDumpBytes = 256;
constexpr std::size_t kInterestingDumpBytes = 4096;
constexpr std::size_t kMaximumQueuedLogLines = 8192;

using BytePattern = std::vector<int>;

bool MatchesPattern(const void* address, const BytePattern& pattern);

const BytePattern kInternalSendSignature = {
    0x48, 0x8b, 0xc4, 0x56, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48,
    0x81, 0xec, 0xc0, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x40};
const BytePattern kDecodedRecordSignature = {
    0x48, 0x8b, 0xc4, 0x55, 0x48, 0x8d, 0x68, -1, 0x48, 0x81, 0xec, 0x90, 0x00,
    0x00, 0x00, 0x48, 0xc7, 0x45, -1, -1, -1, -1, -1, 0x48, 0x89, 0x58, -1,
    0x48, 0x89, 0x70, -1, 0x48, 0x89, 0x78, -1, 0x48, 0x8b, 0xda};
// IDA MCP shortest unique entry signature from the lifted XVersion image.
const BytePattern kMessageDispatchSignature = {
    0x48, 0x89, 0x5c, 0x24, -1, 0x56, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b,
    0x99, -1, -1, -1, -1, 0x44, 0x8b, 0xda};
// IDA shortest unique entry signature for sub_140F9D250, the actor lookup
// used by the native 0x0025/0x0027 movement callbacks.
const BytePattern kMovementActorLookupSignature = {
    0x48, 0x89, 0x6c, 0x24, -1, 0x56, 0x48, 0x83, 0xec, 0x20, 0x44, 0x8b,
    0x05, -1, -1, -1, -1, 0x48, 0x8d, 0x2d, -1, -1, -1, -1, 0x41, 0x8b,
    0xc0, 0x48, 0x8b, 0xf1, 0xc1, 0xe8, 0x08, 0x0f, 0xb6, 0xd0, 0x41, 0x0f,
    0xb6, 0xc0, 0x8b, 0x94, 0x95, -1, -1, -1, -1, 0x44, 0x8b, 0x44, 0x85,
    -1, 0xb8, 0xa1, 0xa0, 0xa0, 0xa0, 0x41, 0x81, 0xc0, 0xaf, 0x16, 0x00,
    0x00, 0x44, 0x03, 0xc2, 0x41, 0xf7, 0xe0, 0xc1, 0xea, 0x06, 0x6b, 0xc2,
    0x66, 0x44, 0x2b, 0xc0, 0x0f, 0xb7, 0x05, -1, -1, -1, -1, 0x41, 0x8b,
    0xc8};
// Actor vtable +384. This forwards the replicated float3 transform to the
// presentation/engine entity returned by Actor vtable +376.
const BytePattern kActorSetPositionSignature = {
    0x48, 0x89, 0x5c, 0x24, -1, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b,
    0x41, -1, 0x48, 0x8b, 0xd9, 0x48, 0x83, 0xc1, 0x18};
// Presentation vtable +1088. Besides toggling the active bit, a true call
// retries creation of the presentation's engine child at +6832 when the
// renderer/world service has become ready.
const BytePattern kPresentationSetActiveSignature = {
    0x48, 0x89, 0x5c, 0x24, -1, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b,
    0x01, 0x0f, 0xb6, 0xfa, 0x48, 0x8b, 0xd9, 0xff, 0x90, -1, -1, -1, -1};
// sub_140F59910 is the local movement/physics synchronization tick. It asks
// the selected movement-state backend to update controller+192, then applies
// that position through the state's vtable +80 callback.
const BytePattern kMovementPhysicsTickSignature = {
    0x40, 0x56, 0x48, 0x81, 0xec, 0xc0, 0x00, 0x00, 0x00};
// sub_140AEE5D0 maps animation/input state transitions to MOVE_1 action IDs.
const BytePattern kMovementStateActionSignature = {
    0x48, 0x89, 0x5c, 0x24, -1, 0x48, 0x89, 0x74, 0x24, -1, 0x57, 0x48,
    0x83, 0xec, 0x20, 0x41, 0x80, 0xb9};
// State 0 vtable +184. The low nibble of its second argument is the actual
// forward/back/left/right input consumed by the ground speed integrator.
const BytePattern kGroundMovementUpdateSignature = {
    0x48, 0x8b, 0xc4, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0xa8, -1, -1, -1, -1, 0x48, 0x81, 0xec, 0xf0, 0x01, 0x00,
    0x00, 0x48, 0xc7, 0x44, 0x24};
// State 14 vtable +184. This backend owns the airborne/glider velocity and
// gravity integration path.
const BytePattern kAirMovementUpdateSignature = {
    0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, -1, 0x48, 0x89, 0x68, -1, 0x48,
    0x89, 0x70, -1, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xec, 0xc0,
    0x00, 0x00, 0x00};
// Client-native Actor speed recalculation. It derives forward, backward, and
// side movement caps from the current Actor state and local movement config,
// then writes them through sub_140B4ADC0.
const BytePattern kActorRecalculateGroundSpeedsSignature = {
    0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xec, 0x50, 0x44,
    0x8b, 0x81};
// Native resource-table lookup used by both the speed-limit and falling
// movement paths with category 1 and Actor+40 as the resource id.
const BytePattern kActorResourceLookupSignature = {
    0x40, 0x57, 0x48, 0x83, 0xec, 0x30, 0x48, 0xc7, 0x44, 0x24, -1, -1, -1,
    -1, -1, 0x48, 0x89, 0x5c, 0x24, -1, 0x48, 0x8b, 0xda, 0x8b, 0xf9};
// sub_140E62E90 selects the concrete forward/side/backward values from the
// Actor resource and clamps each through the global movement configuration.
const BytePattern kMovementSpeedLimitsSignature = {
    0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, -1, 0x48, 0x89, 0x68, -1, 0x48,
    0x89, 0x70, -1, 0x57, 0x48, 0x83, 0xec, 0x60, 0x0f, 0x29, 0x70, -1,
    0x48, 0x8b, 0xfa};
// State 3 vtable +184. This is the ordinary jump/fall collision integrator;
// it produces a candidate velocity and asks Actor+328 to commit the position.
const BytePattern kFallingMovementUpdateSignature = {
    0x4c, 0x8b, 0xdc, 0x4d, 0x89, 0x43, -1, 0x55, 0x53};
// GCloud Connector::Update stop-session handler. The handler vtable query at
// connector+0x188 writes the transport stop reason and extension code to
// connector+0x178/+0x17C before the function dispatches reconnect callbacks.
// This is the shortest unique entry signature generated from the lifted
// XVersion image; installation still waits for the retail image to unpack.
const BytePattern kRelayStopSessionSignature = {
    0x48, 0x8b, 0xc4, 0x57, 0x48, 0x83, 0xec, 0x70, 0x48, 0x8b, 0xf9};
// QQSocketDriver::OnStateChangedProc. This is above Connector::StopSession,
// so it also observes reconnect transitions that bypass the stop handler.
const BytePattern kRelayStateChangedSignature = {
    0x48, 0x8b, 0xc4, 0x55, 0x48, 0x8d, 0x68, -1, 0x48, 0x81, 0xec, 0xa0,
    0x00, 0x00, 0x00, 0x48, 0xc7, 0x45, -1, -1, -1, -1, -1, 0x48, 0x89,
    0x58, -1, 0x48, 0x89, 0x70, -1, 0x48, 0x89, 0x78, -1, 0x4c, 0x89, 0x70,
    -1, 0x49, 0x8b, 0xf9};
// Game-side fallback which starts a reconnect after its connection monitor
// reports a dead LOGIN/World network object.
const BytePattern kForceReconnectSignature = {
    0x40, 0x57, 0x48, 0x83, 0xec, 0x50, 0x48, 0xc7, 0x44, 0x24, -1, -1,
    -1, -1, -1, 0x48, 0x89, 0x5c, 0x24, -1, 0x8b, 0xfa, 0x48, 0x8b, 0x1d};
// GCloud access-layer reconnect entry. Its second argument is forwarded to
// CTGcp::Reconnect and is the best available low-level reason value.
const BytePattern kGCloudReconnectSignature = {
    0x48, 0x89, 0x5c, 0x24, -1, 0x57, 0x48, 0x83, 0xec, 0x30, 0x48, 0x83,
    0xb9, -1, -1, -1, -1, -1, 0x8b, 0xfa};
// sub_141153AF0 is reached only after XVersion's 0x7370 callback accepts the
// active Room panel and begins applying page/list data to the UI.
const BytePattern kRoomListRefreshSignature = {
    0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4c, 0x24, 0x08, 0x55, 0x53,
    0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8d,
    0xac, 0x24, 0x38, 0xfe, 0xff, 0xff};
// sub_141144610 selects/open room page 8 from the first 0x737B branch.
// Signatures below were generated from the lifted XVersion IDB with operand
// wildcarding; the fixed RVA is still verified before either hook is installed.
const BytePattern kRoomPageSelectSignature = {
    0x48, 0x83, 0xec, 0x28, 0xe8, -1, -1, -1, -1, 0x48, 0x85, 0xc0, 0x74,
    -1, 0x48, 0x8d, 0x88, -1, -1, -1, -1, 0xc7, 0x80, -1, -1, -1, -1, -1,
    -1, -1, -1, 0x45, 0x33, 0xc0, 0x48, 0x8d, 0x15, -1, -1, -1, -1, 0xe8,
    -1, -1, -1, -1, 0x48, 0x8b, 0x0d, -1, -1, -1, -1, 0xba, 0x08, 0x00,
    0x00, 0x00};
// sub_141144DF0 builds the in-room AS object and fires InRoomDataRefreshed.
const BytePattern kRoomPageRefreshSignature = {
    0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41,
    0x57, 0x48, 0x8d, 0xac, 0x24, -1, -1, -1, -1, 0xb8, 0xa8, 0x43, 0x00,
    0x00};
// sub_140B3A3C0 writes the selected role RID to EuLobbyCommonData+0xD0.
// The original platform callback reaches this setter after role selection;
// that callback is absent when the preserved client is launched locally.
const BytePattern kSelectedRoleSetterSignature = {
    0x40, 0x57, 0x48, 0x83, 0xec, 0x50, 0x48, 0xc7, 0x44, 0x24, -1, -1,
    -1, -1, -1, 0x48, 0x89, 0x5c, 0x24, -1, 0x48, 0x89, 0x74, 0x24, -1,
    0x48, 0x8b, 0xd9, 0x48, 0x8b, 0x05, -1, -1, -1, -1, 0x48, 0x89,
    0x88};
const BytePattern kPresentationEventSignature = {
    0x48,0x89,0x5c,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x57,0x41,0x54,0x41,0x56,
    0x48,0x83,0xec,0x40,0x4c,0x8b,0x05,-1,-1,-1,-1,0x48,0x8b,0xf1};
const BytePattern kReqJoinInstanceSignature = {
    0x48, 0x83, 0xec, 0x68, 0x48, 0xc7, 0x44, 0x24, -1, -1, -1, -1, -1,
    0x48, 0x89, 0x4c, 0x24};
const BytePattern kInstanceNotifySignature = {
    0x48, 0x85, 0xc9, 0x0f, 0x84, -1, -1, -1, -1, 0x4c, 0x8b, 0xdc, 0x57};
const BytePattern kJoinInstanceRspSignature = {
    0x48, 0x85, 0xc9, 0x0f, 0x84, -1, -1, -1, -1, 0x48, 0x8b, 0xc4, 0x57,
    0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x70};
const BytePattern kStartPointTickSignature = {
    0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0x6c, 0x24, 0xd9, 0x48, 0x81, 0xec, 0xa0, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0x45, 0xa7, 0xfe, 0xff, 0xff, 0xff, 0x48, 0x89, 0x9c, 0x24,
    0xe8, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xf1, 0x80, 0xb9, 0x66, 0x03, 0x00};
const BytePattern kStartPointEventSignature = {
    0x40, 0x56, 0x57, 0x48, 0x83, 0xec, 0x68, 0x4c, 0x8b, 0x49, 0x18, 0x49,
    0x8b, 0xf0, 0x4c, 0x2b, 0xca, 0x48, 0x8b, 0xf9, 0x0f, 0xb6, 0x0a, 0x42,
    0x0f, 0xb6, 0x04, 0x0a};
const BytePattern kMapMouseClickSignature = {
    0x40, 0x56, 0x48, 0x83, 0xec, 0x50, 0x4c, 0x8b, 0x02, 0x48, 0xb8, 0xab,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a, 0x48, 0x8b, 0x52, 0x08, 0x48,
    0x8b, 0xf1, 0x49, 0x2b, 0xd0, 0x48, 0xf7, 0xea, 0x48, 0xc1, 0xfa, 0x02,
    0x48, 0x8b, 0xc2, 0x48, 0xc1, 0xe8, 0x3f, 0x48, 0x03, 0xd0, 0x83, 0xfa};
const BytePattern kMapMouseMoveSignature = {
    0x40, 0x53, 0x48, 0x83, 0xec, 0x60, 0x4c, 0x8b, 0x02, 0x48, 0xb8, 0xab,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a, 0x48, 0x8b, 0x52, 0x08, 0x48,
    0x8b, 0xd9, 0x49, 0x2b, 0xd0, 0x48, 0xf7, 0xea, 0x48, 0xc1, 0xfa, 0x02,
    0x48, 0x8b, 0xc2, 0x48, 0xc1, 0xe8, 0x3f, 0x48, 0x03, 0xd0, 0x83, 0xfa};

bool IsReadableProtection(DWORD protection) {
    if ((protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return false;
    }
    switch (protection & 0xffU) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool IsExecutableProtection(DWORD protection) {
    if ((protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return false;
    }
    switch (protection & 0xffU) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool CopyReadable(const void* source, void* destination, std::size_t size) {
    if (source == nullptr || destination == nullptr || size == 0) {
        return false;
    }
    auto cursor = reinterpret_cast<std::uintptr_t>(source);
    const auto end = cursor + size;
    if (end < cursor) {
        return false;
    }
    auto* output = static_cast<std::uint8_t*>(destination);
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info)) != sizeof(info) ||
            info.State != MEM_COMMIT || !IsReadableProtection(info.Protect)) {
            return false;
        }
        const auto region_end = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
        const auto count = std::min(end, region_end) - cursor;
        std::memcpy(output, reinterpret_cast<const void*>(cursor), count);
        output += count;
        cursor += count;
    }
    return true;
}

template <typename T>
T ReadValue(const void* address) {
    T value{};
    CopyReadable(address, &value, sizeof(value));
    return value;
}

void Log(const char* format, ...);

// The worker can race asynchronous model destruction. ReadProcessMemory
// fails safely on an unmapped range; VirtualQuery followed by memcpy alone
// cannot close that race. These probes never call native virtual methods.
bool ReadRemoteProbeMemory(std::uintptr_t address, void* output, std::size_t size) {
    SIZE_T copied = 0;
    return address && size && ReadProcessMemory(GetCurrentProcess(),
        reinterpret_cast<const void*>(address), output, size, &copied) && copied == size;
}

template <class T>
T RemoteProbeValue(std::uintptr_t address) {
    T value{};
    ReadRemoteProbeMemory(address, &value, sizeof(value));
    return value;
}

bool ReadRemotePresentationPosition(std::uintptr_t presentation,
                                    roe::trace_remote::Position& position) {
    const auto base = g_main_module_base.load(std::memory_order_relaxed);
    const auto table = RemoteProbeValue<std::uintptr_t>(presentation);
    // Only decode the object layout backed by lifted sub_14095A850.
    return base && table && RemoteProbeValue<std::uintptr_t>(table + 464U) ==
        base + (0x14095A850ULL - kPreferredImageBase) &&
        roe::trace_remote::read_position(presentation, ReadRemoteProbeMemory, position);
}

void LogRemoteActorSnapshot(const roe::trace_remote::Entry& entry,
                           const char* source, unsigned message = 0U,
                           unsigned sync_type = 0U) {
    const auto actor = entry.actor;
    std::uint64_t identity{};
    if (!actor || !ReadRemoteProbeMemory(actor + 40U, &identity, sizeof(identity)) ||
        identity != entry.rid) {
        Log("[REMOTE-RENDER] source=%s msg=0x%04X type=%u rid=0x%016llX actor=%p identity_ok=0 observed_rid=0x%016llX",
            source, message, sync_type, static_cast<unsigned long long>(entry.rid),
            reinterpret_cast<void*>(actor), static_cast<unsigned long long>(identity));
        return;
    }
    const auto presentation = RemoteProbeValue<std::uintptr_t>(actor + 48U);
    const auto flags = RemoteProbeValue<std::uint8_t>(actor + 104U);
    const auto child = presentation ? RemoteProbeValue<std::uintptr_t>(presentation + 6832U) : 0U;
    const auto presentation_flags = presentation ? RemoteProbeValue<std::uint32_t>(presentation + 3128U) : 0U;
    const auto model_node = presentation ? RemoteProbeValue<std::uintptr_t>(presentation + 6816U) : 0U;
    const auto holder = RemoteProbeValue<std::uintptr_t>(actor + 176U);
    const auto slot = holder ? RemoteProbeValue<std::uintptr_t>(holder + 48U) : 0U;
    const auto movement = slot ? RemoteProbeValue<std::uintptr_t>(slot) : 0U;
    double cache[3]{};
    const bool cache_ok = movement && RemoteProbeValue<std::uintptr_t>(movement + 784U) == actor &&
        ReadRemoteProbeMemory(movement + 192U, cache, sizeof(cache));
    const auto timeline = cache_ok ? RemoteProbeValue<std::uintptr_t>(movement + 40U) : 0U;
    roe::trace_remote::MotionState motion{};
    const bool motion_ok=roe::trace_remote::read_motion(movement,actor,ReadRemoteProbeMemory,motion);
    roe::trace_remote::PoseState pose{};
    const bool pose_ok=roe::trace_remote::read_pose(actor,ReadRemoteProbeMemory,pose);
    const auto image_base=g_main_module_base.load(std::memory_order_relaxed);
    const auto clock_root=image_base ? RemoteProbeValue<std::uintptr_t>(
        image_base+(0x1431C4BD0ULL-kPreferredImageBase)) : 0U;
    const auto scene_clock=clock_root && clock_root!=std::uintptr_t(-8)
        ? RemoteProbeValue<std::uintptr_t>(clock_root+264U) : 0U;
    const auto queued = timeline ? RemoteProbeValue<std::uint32_t>(timeline + 48U) : 0U;
    const auto first_sample = queued ? RemoteProbeValue<std::uintptr_t>(timeline + 32U) : 0U;
    roe::trace_remote::Position position{}, local_position{};
    const bool position_ok = ReadRemotePresentationPosition(presentation, position);
    const auto local_actor = g_scene_actor_pointer.load(std::memory_order_relaxed);
    const auto local_presentation = local_actor ? RemoteProbeValue<std::uintptr_t>(local_actor + 48U) : 0U;
    const bool local_ok = ReadRemotePresentationPosition(local_presentation, local_position);
    const auto dx = double(position.x) - local_position.x;
    const auto dy = double(position.y) - local_position.y;
    const auto dz = double(position.z) - local_position.z;
    const auto distance = position_ok && local_ok ? std::sqrt(dx*dx + dy*dy + dz*dz) : -1.0;
    const auto component_vtable = RemoteProbeValue<std::uintptr_t>(actor + 24U);
    // A concurrent replacement may make the fields inconsistent. Mark it;
    // do not interpret an old pointer as a freshly created remote character.
    const bool stable = RemoteProbeValue<std::uint64_t>(actor + 40U) == entry.rid &&
        RemoteProbeValue<std::uintptr_t>(actor + 48U) == presentation;
    Log("[REMOTE-RENDER] source=%s msg=0x%04X type=%u rid=0x%016llX actor=%p identity_ok=1 stable=%u "
        "flags=0x%02X inactive=%u state280=%u state312=%u state314=%u state315=%u model264=%u component_vtable=%p "
        "visibility_mask168=0x%08X presentation=%p pflags=0x%08X active=%u pmask=0x%04X prequired=0x%04X resource_ready=%u model_node=%p child=%p child_vtable=%p "
        "pos_ok=%u xyz=(%.3f,%.3f,%.3f) local_pos_ok=%u distance=%.3f "
        "cache_ok=%u cache=(%.3f,%.3f,%.3f) transforms=%llu input_ok=%u input=(%.3f,%.3f,%.3f) "
        "move_clock=%g queued=%u first_clock=%u/%u first_action=%g first_path=%u world_clock=%u/%u enabled=%u mode=%u "
        "motion_ok=%u kind=%u input=0x%02X gait=%u backend=%u velocity=(%.3f,%.3f,%.3f) "
        "pose_ok=%u movement_state=%u desired_state=%d grapple_active=%u grapple_phase=%u anim91_ok=%u anim91=%g",
        source, message, sync_type, static_cast<unsigned long long>(entry.rid),
        reinterpret_cast<void*>(actor), unsigned(stable), unsigned(flags),
        unsigned(RemoteProbeValue<std::uint8_t>(actor + 269U)),
        unsigned(RemoteProbeValue<std::uint8_t>(actor + 280U)),
        unsigned(RemoteProbeValue<std::uint8_t>(actor + 312U)),
        unsigned(RemoteProbeValue<std::uint8_t>(actor + 314U)),
        unsigned(RemoteProbeValue<std::uint8_t>(actor + 315U)),
        RemoteProbeValue<std::uint32_t>(actor + 264U), reinterpret_cast<void*>(component_vtable),
        RemoteProbeValue<std::uint32_t>(actor + 168U),
        reinterpret_cast<void*>(presentation), presentation_flags, unsigned((presentation_flags & 4U) != 0U),
        unsigned(RemoteProbeValue<std::uint16_t>(presentation + 24U)),
        unsigned(RemoteProbeValue<std::uint16_t>(presentation + 26U)),
        unsigned(RemoteProbeValue<std::uint8_t>(presentation + 4848U)),
        reinterpret_cast<void*>(model_node),
        reinterpret_cast<void*>(child), reinterpret_cast<void*>(RemoteProbeValue<std::uintptr_t>(child)),
        unsigned(position_ok), double(position.x), double(position.y), double(position.z), unsigned(local_ok), distance,
        unsigned(cache_ok), cache[0], cache[1], cache[2], static_cast<unsigned long long>(entry.transforms),
        unsigned(entry.input_valid), double(entry.last_input.x), double(entry.last_input.y), double(entry.last_input.z),
        cache_ok ? double(RemoteProbeValue<float>(movement + 104U)) : 0.0, queued,
        first_sample ? RemoteProbeValue<std::uint32_t>(first_sample + 52U) : 0U,
        first_sample ? RemoteProbeValue<std::uint32_t>(first_sample + 56U) : 0U,
        first_sample ? double(RemoteProbeValue<float>(first_sample+276U)) : 0.0,
        first_sample ? RemoteProbeValue<std::uint32_t>(first_sample+288U) : 0U,
        scene_clock ? RemoteProbeValue<std::uint32_t>(scene_clock+132U) : 0U,
        scene_clock ? RemoteProbeValue<std::uint32_t>(scene_clock+124U) : 0U,
        scene_clock ? unsigned(RemoteProbeValue<std::uint8_t>(scene_clock+152U)) : 0U,
        scene_clock ? RemoteProbeValue<std::uint32_t>(scene_clock+156U) : 0U,
        unsigned(motion_ok),unsigned(motion.kind),unsigned(motion.input),motion.gait,motion.backend,
        double(motion.velocity.x),double(motion.velocity.y),double(motion.velocity.z),
        unsigned(pose_ok),pose.state,pose.desired,unsigned(pose.active),pose.phase,
        unsigned(pose.animation_ok),double(pose.animation91));
}

void LogDeployableSnapshot(const roe::trace_remote::Entry& entry,const char* source) {
    const auto entity=entry.actor;
    std::uint64_t identity{};
    const bool identity_ok=entity && ReadRemoteProbeMemory(entity+40U,&identity,8) && identity==entry.rid;
    const auto presentation=identity_ok ? RemoteProbeValue<std::uintptr_t>(entity+48U) : 0U;
    roe::trace_remote::Position position{};
    const bool position_ok=presentation && ReadRemotePresentationPosition(presentation,position);
    Log("[BARRIER-RENDER] source=%s id=0x%016llX entity=%p identity_ok=%u presentation=%p "
        "inactive=%u pending=%u activation=%u hp=%u lifetime=%g "
        "pos_ok=%u xyz=(%.3f,%.3f,%.3f)",
        source,static_cast<unsigned long long>(entry.rid),reinterpret_cast<void*>(entity),
        unsigned(identity_ok),reinterpret_cast<void*>(presentation),
        identity_ok ? unsigned(RemoteProbeValue<std::uint8_t>(entity+269U)) : 0U,
        identity_ok ? unsigned(RemoteProbeValue<std::uint8_t>(entity+400U)) : 0U,
        identity_ok ? unsigned(RemoteProbeValue<std::uint8_t>(entity+404U)) : 0U,
        identity_ok ? RemoteProbeValue<std::uint32_t>(entity+384U) : 0U,
        identity_ok ? double(RemoteProbeValue<float>(entity+388U)) : 0.0,
        unsigned(position_ok),double(position.x),double(position.y),double(position.z));
}

void ProbeRemoteActorStates() {
    static ULONGLONG last_sample = 0;
    const auto now = GetTickCount64();
    if (now - last_sample < 1000U) return;
    last_sample = now;
    std::array<roe::trace_remote::Entry, 64> entries,deployables;
    {
        std::lock_guard lock(g_remote_probe_mutex);
        g_remote_probes.expire(now);
        entries = g_remote_probes.entries();
        g_deployable_probes.expire(now);
        deployables=g_deployable_probes.entries();
    }
    for (const auto& entry : entries) {
        if (InterlockedCompareExchange(&g_stopping, 0, 0) != 0) return;
        if (entry.rid) LogRemoteActorSnapshot(entry, "poll");
    }
    for (const auto& entry:deployables) {
        if (InterlockedCompareExchange(&g_stopping,0,0)!=0) return;
        if (entry.rid) LogDeployableSnapshot(entry,"poll");
    }
}

struct RoomUiTraceState {
    std::uintptr_t room_state{};
    std::uint64_t active_room{};
    std::uintptr_t lobby_common_data{};
    std::uint64_t selected_role{};
    std::uint8_t ui_ready{};
};

RoomUiTraceState ReadRoomUiTraceState() {
    RoomUiTraceState state;
    const auto image_base =
        g_main_module_base.load(std::memory_order_relaxed);
    if (image_base == 0) {
        return state;
    }

    state.room_state = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
        image_base + (kRoomStateGlobalVa - kPreferredImageBase)));
    if (state.room_state != 0) {
        state.active_room = ReadValue<std::uint64_t>(
            reinterpret_cast<const void*>(state.room_state + 208U));
    }
    state.lobby_common_data = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(
            image_base + (kLobbyActorGlobalVa - kPreferredImageBase)));
    if (state.lobby_common_data != 0) {
        state.selected_role = ReadValue<std::uint64_t>(
            reinterpret_cast<const void*>(state.lobby_common_data + 208U));
    }
    state.ui_ready = ReadValue<std::uint8_t>(reinterpret_cast<const void*>(
        image_base + (kRoomUiReadyVa - kPreferredImageBase)));
    return state;
}

void LogRoomUiState(const char* origin, const char* phase,
                    std::int64_t object = 0, unsigned int object_size = 0) {
    const auto state = ReadRoomUiTraceState();
    const auto incoming_room = object != 0
        ? ReadValue<std::uint64_t>(reinterpret_cast<const void*>(object + 4))
        : 0U;
    const auto incoming_creator = object != 0
        ? ReadValue<std::uint64_t>(reinterpret_cast<const void*>(object + 12))
        : 0U;
    Log("[ROOM-UI-STATE] origin=%s phase=%s object=%p native_size=%u "
        "incoming_room=%llu incoming_creator=%llu room_state=%p "
        "active_room=%llu lobby_common_data=%p selected_role=%llu ui_ready=%u",
        origin, phase, reinterpret_cast<void*>(object), object_size,
        static_cast<unsigned long long>(incoming_room),
        static_cast<unsigned long long>(incoming_creator),
        reinterpret_cast<void*>(state.room_state),
        static_cast<unsigned long long>(state.active_room),
        reinterpret_cast<void*>(state.lobby_common_data),
        static_cast<unsigned long long>(state.selected_role),
        static_cast<unsigned>(state.ui_ready));
}

void ProbeMovementActorState(unsigned int message_id, std::int64_t object,
                             unsigned int object_size);
void RefreshLocalSceneActor();

std::string ReadCString(const void* address, std::size_t maximum) {
    std::string result;
    result.reserve(std::min<std::size_t>(maximum, 256));
    const auto* cursor = static_cast<const char*>(address);
    for (std::size_t index = 0; index < maximum; ++index) {
        char character = 0;
        if (!CopyReadable(cursor + index, &character, 1)) {
            return result.empty() ? "<unreadable>" : result + "<unreadable>";
        }
        if (character == '\0') {
            return result;
        }
        if (static_cast<unsigned char>(character) < 0x20U ||
            static_cast<unsigned char>(character) >= 0x7fU) {
            result.push_back('.');
        } else {
            result.push_back(character);
        }
    }
    return result + "<truncated>";
}

void EnsureLogFile() {
    if (g_log_file != INVALID_HANDLE_VALUE) {
        return;
    }
    wchar_t temp_path[MAX_PATH]{};
    const DWORD length = GetTempPathW(static_cast<DWORD>(std::size(temp_path)), temp_path);
    if (length == 0 || length >= std::size(temp_path)) {
        return;
    }
    wchar_t file_name[96]{};
    std::swprintf(file_name, std::size(file_name), L"roe_trace_%lu.log", GetCurrentProcessId());
    std::wstring path(temp_path, length);
    path += file_name;
    g_log_file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

void InitializeConsole() {
    if (GetConsoleWindow() == nullptr) {
        if (!AllocConsole()) return;
        g_owned_console = true;
    }
    SetConsoleTitleW(L"Ring of Elysium - roe_trace");
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Use our own handle, not the host's CRT stdout/stderr. They must remain
    // usable after this DLL and its optional console have gone away.
    g_console_output = CreateFileW(
        L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    // Closing an allocated console can terminate its GUI client. Remove the
    // close command; minimizing the window remains available.
    if (const HWND window = GetConsoleWindow()) {
        if (const HMENU menu = GetSystemMenu(window, FALSE)) {
            DeleteMenu(menu, SC_CLOSE, MF_BYCOMMAND);
            DrawMenuBar(window);
        }
    }
}

void WriteConsoleLine(const std::string& line) {
    if (g_console_output == INVALID_HANDLE_VALUE) {
        return;
    }
    const bool message_line = line.find("[PLAIN-IN]") != std::string::npos ||
                              line.find("[PLAIN-OUT]") != std::string::npos;
    const auto marker = message_line ? line.find("name=") : std::string::npos;
    if (marker == std::string::npos) {
        DWORD written = 0;
        WriteFile(g_console_output, line.data(), static_cast<DWORD>(line.size()),
                  &written, nullptr);
        return;
    }
    const auto name_begin = marker + 5U;
    const auto name_end = line.find_first_of(" \r\n", name_begin);
    if (name_end == std::string::npos || name_end == name_begin) {
        DWORD written = 0;
        WriteFile(g_console_output, line.data(), static_cast<DWORD>(line.size()),
                  &written, nullptr);
        return;
    }

    CONSOLE_SCREEN_BUFFER_INFO info{};
    const WORD original = GetConsoleScreenBufferInfo(g_console_output, &info)
                              ? info.wAttributes
                              : static_cast<WORD>(FOREGROUND_RED | FOREGROUND_GREEN |
                                                  FOREGROUND_BLUE);
    DWORD written = 0;
    WriteFile(g_console_output, line.data(), static_cast<DWORD>(name_begin),
              &written, nullptr);
    SetConsoleTextAttribute(g_console_output,
                            FOREGROUND_GREEN | FOREGROUND_BLUE |
                                FOREGROUND_INTENSITY);
    WriteFile(g_console_output, line.data() + name_begin,
              static_cast<DWORD>(name_end - name_begin), &written, nullptr);
    SetConsoleTextAttribute(g_console_output, original);
    WriteFile(g_console_output, line.data() + name_end,
              static_cast<DWORD>(line.size() - name_end), &written, nullptr);
}

void WriteLogLine(const std::string& line) {
    EnsureLogFile();
    if (g_log_file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(g_log_file, line.data(), static_cast<DWORD>(line.size()),
                  &written, nullptr);
    }
    WriteConsoleLine(line);
    OutputDebugStringA(line.c_str());
}

DWORD WINAPI LogWriter(void*) {
    for (;;) {
        std::deque<std::string> pending;
        {
            std::unique_lock lock(g_log_queue_mutex);
            g_log_queue_ready.wait_for(lock, std::chrono::milliseconds(250), [] {
                return !g_log_queue.empty() ||
                       g_log_stopping.load();
            });
            pending.swap(g_log_queue);
            if (pending.empty() &&
                g_log_stopping.load()) {
                break;
            }
        }
        for (const auto& line : pending) {
            WriteLogLine(line);
        }
        const auto dropped =
            g_dropped_log_lines.exchange(0, std::memory_order_relaxed);
        if (dropped != 0) {
            char warning[160]{};
            const int size = std::snprintf(
                warning, sizeof(warning),
                "[TRACE] async-log queue full dropped=%u lines\r\n", dropped);
            if (size > 0) {
                WriteLogLine(std::string(
                    warning, static_cast<std::size_t>(std::min<int>(
                                 size, static_cast<int>(sizeof(warning) - 1)))));
            }
        }
    }
    return 0;
}

void StartLogWriter() {
    bool expected = false;
    if (!g_log_writer_started.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return;
    }
    const HANDLE thread = CreateThread(nullptr, 0, &LogWriter, nullptr, 0, nullptr);
    if (thread == nullptr) {
        g_log_writer_started.store(false, std::memory_order_release);
        OutputDebugStringA("roe_trace: failed to start async log writer\r\n");
        return;
    }
    g_log_writer_thread = thread;
}

void Log(const char* format, ...) {

    char message[8192]{};
    va_list arguments;
    va_start(arguments, format);
    const int message_length = std::vsnprintf(message, sizeof(message), format, arguments);
    va_end(arguments);
    if (message_length <= 0) {
        return;
    }

    SYSTEMTIME time{};
    GetLocalTime(&time);
    char line[8448]{};
    const int line_length = std::snprintf(
        line, sizeof(line), "%02u:%02u:%02u.%03u [tid=%lu] %.*s\r\n", time.wHour,
        time.wMinute, time.wSecond, time.wMilliseconds, GetCurrentThreadId(),
        static_cast<int>(sizeof(message) - 1), message);
    if (line_length <= 0) {
        return;
    }
    const auto bytes = static_cast<std::size_t>(
        std::min<int>(line_length, static_cast<int>(sizeof(line) - 1)));
    if (!g_log_writer_started.load(std::memory_order_acquire)) {
        WriteLogLine(std::string(line, bytes));
        return;
    }
    {
        std::lock_guard lock(g_log_queue_mutex);
        if (g_log_queue.size() >= kMaximumQueuedLogLines) {
            g_dropped_log_lines.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        g_log_queue.emplace_back(line, bytes);
    }
    g_log_queue_ready.notify_one();
}

std::string HexBytes(const void* address, std::size_t size, std::size_t limit) {
    if (address == nullptr || size == 0) {
        return "";
    }
    const auto count = std::min(size, limit);
    std::vector<std::uint8_t> bytes(count);
    if (!CopyReadable(address, bytes.data(), count)) {
        return "<unreadable>";
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(count * 2U + 16U);
    for (const auto byte : bytes) {
        result.push_back(digits[byte >> 4U]);
        result.push_back(digits[byte & 0x0fU]);
    }
    if (count < size) {
        result += "...";
    }
    return result;
}

bool ForceMoveSyncDispatchEnabled() {
    char value[8]{};
    const auto length = GetEnvironmentVariableA(
        "ROE_TRACE_FORCE_MOVE_SYNC", value, static_cast<DWORD>(std::size(value)));
    return length != 0U && length < std::size(value) && value[0] == '1';
}

bool ForcePresentationActiveEnabled() {
    char value[8]{};
    const auto length = GetEnvironmentVariableA(
        "ROE_TRACE_FORCE_PRESENTATION_ACTIVE", value,
        static_cast<DWORD>(std::size(value)));
    return length != 0U && length < std::size(value) && value[0] == '1';
}

bool RecalculateGroundSpeedsEnabled() {
    char value[8]{};
    const auto length = GetEnvironmentVariableA(
        "ROE_TRACE_RECALC_GROUND_SPEEDS", value,
        static_cast<DWORD>(std::size(value)));
    return length != 0U && length < std::size(value) && value[0] == '1';
}

std::string FormatAddress(const sockaddr* address, int address_length) {
    if (address == nullptr || address_length < static_cast<int>(sizeof(address->sa_family))) {
        return "<null>";
    }
    char host[INET6_ADDRSTRLEN]{};
    char result[160]{};
    if (address->sa_family == AF_INET && address_length >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        if (InetNtopA(AF_INET, const_cast<IN_ADDR*>(&ipv4->sin_addr), host, sizeof(host))) {
            std::snprintf(result, sizeof(result), "%s:%u", host,
                          static_cast<unsigned>(ntohs(ipv4->sin_port)));
            return result;
        }
    } else if (address->sa_family == AF_INET6 &&
               address_length >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        if (InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&ipv6->sin6_addr), host, sizeof(host))) {
            std::snprintf(result, sizeof(result), "[%s]:%u", host,
                          static_cast<unsigned>(ntohs(ipv6->sin6_port)));
            return result;
        }
    }
    return "<family-" + std::to_string(static_cast<unsigned>(address->sa_family)) + ">";
}

bool IsNoisyMessage(std::uint16_t message_id) {
    switch (message_id) {
    case 0x0029:
    case 0x002a:
    case 0x0034:
    case 0x1309:
    case 0x11d7:
    case 0x11d8:
    case 0x11d9:
    case 0x11da:
    case 0x1f74:
    case 0x1f75:
    case 0x3783:
    case 0x7384:
    case 0x7385:
        return true;
    default:
        return false;
    }
}

bool IsInterestingMessage(std::uint16_t message_id) {
    return message_id == 0x0533 || message_id == 0x053d || message_id == 0x1069 ||
           message_id == 0x0553 || message_id == 0x0564 || message_id == 0x0565 ||
           message_id == 0x0be7 || message_id == 0x0dcf ||
           message_id == 0x73a1 || message_id == 0x73a2 ||
           (message_id >= 0x0320 && message_id <= 0x032f) ||
           (message_id >= 0x0400 && message_id <= 0x040f) ||
           (message_id >= 0x0d70 && message_id <= 0x0d7f) ||
           (message_id >= 0x3970 && message_id <= 0x397f) ||
           (message_id >= 0x6e20 && message_id <= 0x6e3f) ||
           (message_id >= 0x7370 && message_id <= 0x7390);
}

void DumpEnterRoomRecordOnce(const void* record, std::size_t record_size) {
    bool expected = false;
    if (!g_enter_room_record_dumped.compare_exchange_strong(
            expected, true, std::memory_order_relaxed) ||
        record == nullptr || record_size == 0 || record_size > 1024U * 1024U) {
        return;
    }

    std::vector<std::uint8_t> copy(record_size);
    if (!CopyReadable(record, copy.data(), copy.size())) {
        Log("[SCENE-AVATAR] 0x0DCF record copy failed bytes=%zu", record_size);
        return;
    }

    wchar_t temp_path[MAX_PATH]{};
    const DWORD length =
        GetTempPathW(static_cast<DWORD>(std::size(temp_path)), temp_path);
    if (length == 0 || length >= std::size(temp_path)) {
        Log("[SCENE-AVATAR] 0x0DCF temp path unavailable");
        return;
    }
    wchar_t file_name[128]{};
    std::swprintf(file_name, std::size(file_name),
                  L"roe_scene_0dcf_%lu.bin", GetCurrentProcessId());
    std::wstring path(temp_path, length);
    path += file_name;
    const HANDLE file = CreateFileW(
        path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        Log("[SCENE-AVATAR] 0x0DCF dump open failed error=%lu",
            GetLastError());
        return;
    }
    DWORD written = 0;
    const bool ok = WriteFile(file, copy.data(),
                              static_cast<DWORD>(copy.size()), &written,
                              nullptr) != FALSE &&
                    written == copy.size();
    CloseHandle(file);
    Log("[SCENE-AVATAR] 0x0DCF dump %s bytes=%zu file=roe_scene_0dcf_%lu.bin",
        ok ? "written" : "failed", record_size, GetCurrentProcessId());
}

std::string LookupMessageName(std::uint16_t message_id) {
    return std::string(roe::message_name(message_id));
}

void DumpMessageNames() {
    bool expected = false;
    if (!g_message_names_dumped.compare_exchange_strong(
            expected, true, std::memory_order_relaxed)) {
        return;
    }

    wchar_t temp_path[MAX_PATH]{};
    const DWORD length =
        GetTempPathW(static_cast<DWORD>(std::size(temp_path)), temp_path);
    if (length == 0 || length >= std::size(temp_path)) {
        Log("[MSG-NAMES] temp path unavailable");
        return;
    }
    wchar_t file_name[128]{};
    std::swprintf(file_name, std::size(file_name),
                  L"roe_message_names_%lu.tsv", GetCurrentProcessId());
    std::wstring path(temp_path, length);
    path += file_name;
    const HANDLE file = CreateFileW(
        path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        Log("[MSG-NAMES] dump open failed error=%lu", GetLastError());
        return;
    }

    const char header[] = "id_hex\tid_unsigned\tid_signed\tname\r\n";
    DWORD written = 0;
    WriteFile(file, header, static_cast<DWORD>(sizeof(header) - 1), &written, nullptr);
    const auto* names = roe::message_names_data();
    const auto known = roe::message_names_size();
    for (std::size_t index = 0; index < known; ++index) {
        const auto message_id = names[index].id;
        const auto name = names[index].name;
        char line[512]{};
        const int line_length = std::snprintf(
            line, sizeof(line), "0x%04X\t%u\t%d\t%s\r\n",
            static_cast<unsigned>(message_id), static_cast<unsigned>(message_id),
            static_cast<int>(static_cast<std::int16_t>(message_id)), name.data());
        if (line_length <= 0) {
            continue;
        }
        const auto line_bytes = static_cast<DWORD>(
            std::min<int>(line_length, static_cast<int>(sizeof(line) - 1)));
        if (!WriteFile(file, line, line_bytes, &written, nullptr)) {
            Log("[MSG-NAMES] write failed id=0x%04X error=%lu",
                static_cast<unsigned>(message_id), GetLastError());
            break;
        }
    }
    FlushFileBuffers(file);
    CloseHandle(file);
    Log("[MSG-NAMES] dumped=%zu source=ida-static path=%ls", known, path.c_str());
}

bool ShouldLog(std::array<std::atomic<std::uint32_t>, 65536>& counts,
               std::uint16_t message_id, std::uint32_t& occurrence) {
    occurrence = counts[message_id].fetch_add(1, std::memory_order_relaxed) + 1;
    return !IsNoisyMessage(message_id) || occurrence == 1 || (occurrence % 50U) == 0;
}

void LogUdpStackOnce() {
    bool expected = false;
    if (!g_udp_stack_logged.compare_exchange_strong(
            expected, true, std::memory_order_relaxed)) {
        return;
    }

    std::array<void*, 24> frames{};
    const auto count = CaptureStackBackTrace(
        0, static_cast<DWORD>(frames.size()), frames.data(), nullptr);
    for (USHORT index = 0; index < count; ++index) {
        HMODULE module = nullptr;
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(frames[index]), &module)) {
            Log("[UDP-STACK] frame=%u address=%p module=<unknown>",
                static_cast<unsigned>(index), frames[index]);
            continue;
        }
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(module, path, static_cast<DWORD>(std::size(path)));
        const auto rva = reinterpret_cast<std::uintptr_t>(frames[index]) -
                         reinterpret_cast<std::uintptr_t>(module);
        Log("[UDP-STACK] frame=%u address=%p module=%ls rva=0x%llx",
            static_cast<unsigned>(index), frames[index], path,
            static_cast<unsigned long long>(rva));
    }
}

void LogStackFrames(const char* label) {
    std::array<void*, 32> frames{};
    const auto count = CaptureStackBackTrace(
        0, static_cast<DWORD>(frames.size()), frames.data(), nullptr);
    for (USHORT index = 0; index < count; ++index) {
        HMODULE module = nullptr;
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(frames[index]), &module)) {
            Log("[%s] frame=%u address=%p module=<unknown>", label,
                static_cast<unsigned>(index), frames[index]);
            continue;
        }
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(module, path, static_cast<DWORD>(std::size(path)));
        const auto rva = reinterpret_cast<std::uintptr_t>(frames[index]) -
                         reinterpret_cast<std::uintptr_t>(module);
        Log("[%s] frame=%u address=%p module=%ls rva=0x%llx", label,
            static_cast<unsigned>(index), frames[index], path,
            static_cast<unsigned long long>(rva));
    }
}

const char* RelayStopReasonName(std::int32_t reason) {
    static constexpr std::array<const char*, 36> kNames = {
        "Success",
        "IdleClose",
        "PeerClose",
        "NetworkFailed",
        "BadPackageLen",
        "ExceedLimit",
        "TConndShutDown",
        "GameServerClose",
        "AuthFailed",
        "SynAckFailed",
        "WriteBufferFull",
        "ClientSequenceInvalid",
        "TransRelay",
        "TransReleased",
        "RelayClientAuthFailed",
        "SessionKeyRenewFailed",
        "RecvBufferFull",
        "UnpackFailed",
        "InvalidPackage",
        "InvalidSkey",
        "AnotherVerifyTask",
        "ClientProtocolClose",
        "PreRelayFailed",
        "SystemError",
        "ClientStartReconnect",
        "GenDhKeyFailed",
        "IdMappingFailed",
        "WaitingGameServerStart",
        "RoutingFailed",
        "TConndUnreachable",
        "LoginNewGameServer",
        "RouteNotFound",
        "ClusterWaitQueueTimeout",
        "ClusterPushQueueFailed",
        "AuthParamInvalid",
        "GetClusterRouteFailed",
    };
    if (reason < 0 || static_cast<std::size_t>(reason) >= kNames.size()) {
        return "Unknown";
    }
    return kNames[static_cast<std::size_t>(reason)];
}

std::uint8_t __fastcall HookRelayStopSession(std::uintptr_t connector) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto handler = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(connector + 0x188U));
    const auto state_before = ReadValue<std::uint32_t>(
        reinterpret_cast<const void*>(connector + 0x230U));
    const auto connected_before = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(connector + 0x1DBU));
    const auto auto_reconnect_before = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(connector + 0x1DEU));
    const auto connecting_before = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(connector + 0x1DFU));
    const auto reconnecting_before = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(connector + 0x1E0U));
    const auto relay_connecting_before = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(connector + 0x1E1U));

    const auto result = g_relay_stop_session_hook.unsafe_fastcall<std::uint8_t>(
        connector);

    const auto reason = ReadValue<std::int32_t>(
        reinterpret_cast<const void*>(connector + 0x178U));
    const auto extension = ReadValue<std::int32_t>(
        reinterpret_cast<const void*>(connector + 0x17CU));
    const auto state_after = ReadValue<std::uint32_t>(
        reinterpret_cast<const void*>(connector + 0x230U));
    const auto connected_after = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(connector + 0x1DBU));
    const auto connecting_after = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(connector + 0x1DFU));
    const auto reconnecting_after = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(connector + 0x1E0U));
    const auto relay_connecting_after = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(connector + 0x1E1U));

    Log("[RELAY-STOP] connector=%p handler=%p reason=%d name=%s ext=%d "
        "result=%u state=%u->%u connected=%u->%u auto_reconnect=%u "
        "connecting=%u->%u reconnecting=%u->%u relay_connecting=%u->%u",
        reinterpret_cast<void*>(connector), reinterpret_cast<void*>(handler),
        reason, RelayStopReasonName(reason), extension,
        static_cast<unsigned>(result), state_before, state_after,
        static_cast<unsigned>(connected_before),
        static_cast<unsigned>(connected_after),
        static_cast<unsigned>(auto_reconnect_before),
        static_cast<unsigned>(connecting_before),
        static_cast<unsigned>(connecting_after),
        static_cast<unsigned>(reconnecting_before),
        static_cast<unsigned>(reconnecting_after),
        static_cast<unsigned>(relay_connecting_before),
        static_cast<unsigned>(relay_connecting_after));
    return result;
}

const char* RelayStateName(int state) {
    switch (state) {
    case 1:
        return "Reconnecting";
    case 2:
        return "Reconnected";
    case 4:
        return "Failed";
    default:
        return "Other";
    }
}

std::uintptr_t __fastcall HookRelayStateChanged(
    std::uintptr_t callback, std::uintptr_t connector, int state,
    std::uintptr_t connector_result) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto result_vtable = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(connector_result));
    const auto result_code = ReadValue<std::int32_t>(
        reinterpret_cast<const void*>(connector_result + 0x8U));
    const auto result_flag = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(connector_result + 0xCU));
    const auto connector_code = ReadValue<std::int32_t>(
        reinterpret_cast<const void*>(connector_result + 0x10U));
    const auto connector_extension = ReadValue<std::int32_t>(
        reinterpret_cast<const void*>(connector_result + 0x14U));
    Log("[RELAY-STATE] phase=before callback=%p connector=%p state=%d name=%s "
        "result=%p vtable=%p result_code=%d flag=%u connector_code=%d ext=%d",
        reinterpret_cast<void*>(callback), reinterpret_cast<void*>(connector),
        state, RelayStateName(state),
        reinterpret_cast<void*>(connector_result),
        reinterpret_cast<void*>(result_vtable), result_code,
        static_cast<unsigned>(result_flag), connector_code,
        connector_extension);
    LogStackFrames("RELAY-STATE-STACK");
    const auto value =
        g_relay_state_changed_hook.unsafe_fastcall<std::uintptr_t>(
            callback, connector, state, connector_result);
    Log("[RELAY-STATE] phase=after state=%d name=%s return=%p",
        state, RelayStateName(state), reinterpret_cast<void*>(value));
    return value;
}

std::int64_t __fastcall HookForceReconnect(std::uintptr_t owner, int network) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    Log("[FORCE-RECONNECT] phase=before owner=%p network=%d",
        reinterpret_cast<void*>(owner), network);
    LogStackFrames("FORCE-RECONNECT-STACK");
    const auto result = g_force_reconnect_hook.unsafe_fastcall<std::int64_t>(
        owner, network);
    Log("[FORCE-RECONNECT] phase=after network=%d result=%lld", network,
        static_cast<long long>(result));
    return result;
}

std::int64_t __fastcall HookGCloudReconnect(std::uintptr_t connector,
                                            unsigned int reason) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto tgcp = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(connector + 0x1C0U));
    const auto previous_reconnect_ms = ReadValue<std::uint64_t>(
        reinterpret_cast<const void*>(connector + 0x1E8U));
    Log("[GCLOUD-RECONNECT] phase=before connector=%p tgcp=%p reason=%u "
        "previous_ms=%llu",
        reinterpret_cast<void*>(connector), reinterpret_cast<void*>(tgcp),
        reason, static_cast<unsigned long long>(previous_reconnect_ms));
    LogStackFrames("GCLOUD-RECONNECT-STACK");
    const auto result = g_gcloud_reconnect_hook.unsafe_fastcall<std::int64_t>(
        connector, reason);
    const auto reconnect_ms = ReadValue<std::uint64_t>(
        reinterpret_cast<const void*>(connector + 0x1E8U));
    Log("[GCLOUD-RECONNECT] phase=after reason=%u result=%lld reconnect_ms=%llu",
        reason, static_cast<long long>(result),
        static_cast<unsigned long long>(reconnect_ms));
    return result;
}

int WSAAPI HookConnect(SOCKET socket, const sockaddr* address, int address_length) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto endpoint = FormatAddress(address, address_length);
    Log("[SOCKET] connect socket=%llu endpoint=%s", static_cast<unsigned long long>(socket),
        endpoint.c_str());
    const int result = g_connect_hook.unsafe_stdcall<int>(socket, address, address_length);
    const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    Log("[SOCKET] connect-result socket=%llu endpoint=%s result=%d wsa=%d",
        static_cast<unsigned long long>(socket), endpoint.c_str(), result, error);
    return result;
}

int WSAAPI HookSendTo(SOCKET socket, const char* buffer, int length, int flags,
                      const sockaddr* address, int address_length) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto event = g_udp_events.fetch_add(1, std::memory_order_relaxed) + 1;
    if (event <= 100 || (event % 1000U) == 0) {
        Log("[UDP-OUT] n=%u socket=%llu endpoint=%s bytes=%d hex=%s", event,
            static_cast<unsigned long long>(socket), FormatAddress(address, address_length).c_str(),
            length, HexBytes(buffer, length > 0 ? static_cast<std::size_t>(length) : 0, 192).c_str());
    }
    if (length == 24) {
        LogUdpStackOnce();
    }
    return g_sendto_hook.unsafe_stdcall<int>(socket, buffer, length, flags, address, address_length);
}

int WSAAPI HookRecvFrom(SOCKET socket, char* buffer, int length, int flags,
                        sockaddr* address, int* address_length) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const int result = g_recvfrom_hook.unsafe_stdcall<int>(socket, buffer, length, flags, address,
                                                           address_length);
    const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (result == SOCKET_ERROR && error == WSAEWOULDBLOCK) {
        return result;
    }
    const auto event = g_udp_events.fetch_add(1, std::memory_order_relaxed) + 1;
    if (event <= 100 || (event % 1000U) == 0 || result == SOCKET_ERROR) {
        const int endpoint_length = address_length != nullptr ? *address_length : 0;
        Log("[UDP-IN] n=%u socket=%llu endpoint=%s bytes=%d wsa=%d hex=%s", event,
            static_cast<unsigned long long>(socket), FormatAddress(address, endpoint_length).c_str(),
            result, error,
            HexBytes(buffer, result > 0 ? static_cast<std::size_t>(result) : 0, 192).c_str());
    }
    return result;
}

char __fastcall HookInternalSend(std::int64_t transport, unsigned int message_id,
                                 const void* object, int object_size, unsigned int flags) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto id = static_cast<std::uint16_t>(message_id);
    std::uint32_t occurrence = 0;
    if (ShouldLog(g_outgoing_counts, id, occurrence)) {
        const auto name = LookupMessageName(id);
        const auto safe_size = object_size > 0 ? static_cast<std::size_t>(object_size) : 0;
        const auto limit = IsInterestingMessage(id) ? kInterestingDumpBytes : kDefaultDumpBytes;
        Log("[PLAIN-OUT] n=%u msg=0x%04X name=%s native_size=%d flags=0x%08X object=%p hex=%s",
            occurrence, message_id, name.empty() ? "<unknown>" : name.c_str(), object_size, flags, object,
            HexBytes(object, safe_size, limit).c_str());
    }
    if (message_id == 0x002aU && object != nullptr && object_size >= 16) {
        const auto move_x = ReadValue<std::uint32_t>(
            static_cast<const std::uint8_t*>(object) + 4U);
        // The selection transport is near X=404803, while the retained
        // Gameplay road spawn is near X=364300. Capture the producer stack at
        // the first post-transition MOVE_1 so IDA can follow the local input
        // and character-controller gate instead of the network serializer.
        if (move_x != 0U && move_x < 390000U &&
            !g_gameplay_move_stack_logged.exchange(
                true, std::memory_order_relaxed)) {
            Log("[GAMEPLAY-MOVE-STACK] first MOVE_1 x=%u object=%p size=%d",
                move_x, object, object_size);
            LogStackFrames("GAMEPLAY-MOVE-STACK");
        }
    }
    return g_internal_send_hook.unsafe_fastcall<char>(transport, message_id, object, object_size,
                                                       flags);
}

std::int64_t __fastcall HookDecodedRecord(std::int64_t parser, std::uint8_t* decoded_header,
                                          std::int64_t context, char* record, int record_size,
                                          int* consumed) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    std::uint16_t message_id = 0;
    std::uint32_t sequence = 0;
    std::array<std::uint8_t, 6> header{};
    if (record_size >= static_cast<int>(header.size()) &&
        CopyReadable(record, header.data(), header.size())) {
        sequence = (static_cast<std::uint32_t>(header[0]) << 24U) |
                   (static_cast<std::uint32_t>(header[1]) << 16U) |
                   (static_cast<std::uint32_t>(header[2]) << 8U) |
                   static_cast<std::uint32_t>(header[3]);
        message_id = static_cast<std::uint16_t>((static_cast<std::uint16_t>(header[4]) << 8U) |
                                                static_cast<std::uint16_t>(header[5]));
    }
    if (message_id == 0x02efU && record_size >= 0x26) {
        // Decrypted 0x02EF application layout: actor count at +0x1C and the
        // first actor's big-endian RID at +0x1E. Keep this only as the
        // candidate selected by the missing offline platform callback.
        std::array<std::uint8_t, 10> actor_header{};
        if (CopyReadable(record + 0x1c, actor_header.data(),
                         actor_header.size())) {
            const auto actor_count = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(actor_header[0]) << 8U) |
                static_cast<std::uint16_t>(actor_header[1]));
            std::uint64_t actor_rid = 0;
            for (std::size_t index = 2; index < actor_header.size(); ++index) {
                actor_rid = (actor_rid << 8U) | actor_header[index];
            }
            if (actor_count != 0 && actor_rid != 0) {
                g_login_world_actor_rid.store(actor_rid,
                                               std::memory_order_release);
                Log("[LOBBY-ROLE] 0x02EF candidate_role=%llu actors=%u",
                    static_cast<unsigned long long>(actor_rid),
                    static_cast<unsigned>(actor_count));
            }
        }
    }
    std::uint32_t occurrence = 0;
    if (ShouldLog(g_incoming_counts, message_id, occurrence)) {
        const auto name = LookupMessageName(message_id);
        const auto safe_size = record_size > 0 ? static_cast<std::size_t>(record_size) : 0;
        if (message_id == 0x0dcf) {
            DumpEnterRoomRecordOnce(record, safe_size);
        }
        const auto limit = IsInterestingMessage(message_id) ? kInterestingDumpBytes : kDefaultDumpBytes;
        Log("[PLAIN-IN] n=%u seq=%u msg=0x%04X name=%s record_size=%d hex=%s", occurrence,
            sequence, static_cast<unsigned>(message_id),
            name.empty() ? "<unknown>" : name.c_str(), record_size,
            HexBytes(record, safe_size, limit).c_str());
    }
    const int consumed_before = consumed != nullptr ? *consumed : -1;
    const auto result = g_decoded_record_hook.unsafe_fastcall<std::int64_t>(
        parser, decoded_header, context, record, record_size, consumed);
    const bool movement_or_actor_snapshot =
        (message_id >= 0x0025U && message_id <= 0x003aU) ||
        message_id == 0x003cU || message_id == 0x049dU ||
        message_id == 0x74d0U || message_id == 0x74cfU ||
        message_id == 0x0547U || message_id == 0x11d4U ||
        message_id == 0x11d6U || message_id == 0x11d8U ||
        message_id == 0x0be7U || message_id == 0x74d0U ||
        message_id == 0x654bU || message_id == 0x6595U;
    if (movement_or_actor_snapshot) {
        const int consumed_after = consumed != nullptr ? *consumed : -1;
        Log("[PLAIN-DECODE] seq=%u wire_msg=0x%04X result=0x%llX "
            "consumed_before=%d consumed_after=%d decoded=%p hex=%s",
            sequence, static_cast<unsigned>(message_id),
            static_cast<unsigned long long>(result), consumed_before,
            consumed_after, decoded_header,
            HexBytes(decoded_header, 128U, 128U).c_str());
    }
    if (message_id == 0x0028U && result == 0x0028 && decoded_header != nullptr &&
        ForceMoveSyncDispatchEnabled()) {
        const auto dispatcher =
            g_last_message_dispatcher.load(std::memory_order_acquire);
        if (dispatcher != 0U && g_message_dispatch_hook) {
            // XVersion decodes MOVE_SYNC_1 successfully but its ordered Scene
            // layer never calls the registered local-position handler. Use
            // the same native object pointer/size that the normal caller would
            // pass to sub_14097ABD0. Calling the trampoline avoids recursively
            // entering HookMessageDispatch.
            const auto forced_result =
                g_message_dispatch_hook.unsafe_fastcall<std::int64_t>(
                    static_cast<std::int64_t>(dispatcher), 0x0028U,
                    reinterpret_cast<std::int64_t>(decoded_header + 6U),
                    static_cast<unsigned int>(record_size));
            Log("[MOVEMENT-COMPAT] forced msg=0x0028 dispatcher=%p "
                "object=%p native_size=%d result=0x%llX",
                reinterpret_cast<void*>(dispatcher), decoded_header + 6U,
                record_size,
                static_cast<unsigned long long>(forced_result));
        } else {
            Log("[MOVEMENT-COMPAT] skipped msg=0x0028 dispatcher=%p hook=%u",
                reinterpret_cast<void*>(dispatcher),
                static_cast<unsigned>(static_cast<bool>(g_message_dispatch_hook)));
        }
    }
    return result;
}

struct RegisteredHandler {
    std::uintptr_t callback = 0;
    std::uintptr_t context = 0;
    const char* table = "none";
};

RegisteredHandler FindRegisteredHandler(std::uintptr_t dispatcher,
                                        unsigned int message_id) {
    const auto find_in_table = [message_id](std::uintptr_t buckets,
                                            std::uint32_t bucket_count,
                                            std::size_t callback_offset,
                                            std::size_t context_offset,
                                            std::size_t next_offset,
                                            const char* table) {
        RegisteredHandler found;
        if (buckets == 0 || bucket_count == 0) return found;
        const auto sentinel = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
            buckets + sizeof(std::uintptr_t) * bucket_count));
        auto node = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
            buckets + sizeof(std::uintptr_t) * (message_id % bucket_count)));
        for (std::size_t depth = 0; node != 0 && depth < 512U; ++depth) {
            if (ReadValue<std::uint32_t>(reinterpret_cast<const void*>(node)) ==
                message_id) {
                if (node == sentinel) return found;
                found.callback = ReadValue<std::uintptr_t>(
                    reinterpret_cast<const void*>(node + callback_offset));
                found.context = ReadValue<std::uintptr_t>(
                    reinterpret_cast<const void*>(node + context_offset));
                found.table = table;
                return found;
            }
            node = ReadValue<std::uintptr_t>(
                reinterpret_cast<const void*>(node + next_offset));
        }
        return found;
    };

    if (dispatcher == 0) return {};
    auto found = find_in_table(
        ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(dispatcher + 152U)),
        ReadValue<std::uint32_t>(reinterpret_cast<const void*>(dispatcher + 160U)),
        24U, 16U, 32U, "primary");
    if (found.callback != 0) return found;
    return find_in_table(
        ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(dispatcher + 72U)),
        ReadValue<std::uint32_t>(reinterpret_cast<const void*>(dispatcher + 80U)),
        8U, 0U, 16U, "fallback");
}

std::int64_t __fastcall HookMessageDispatch(std::int64_t dispatcher,
                                            unsigned int message_id,
                                            std::int64_t object,
                                            unsigned int object_size) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    g_last_message_dispatcher.store(static_cast<std::uintptr_t>(dispatcher),
                                    std::memory_order_release);
    const bool movement_message =
        (message_id >= 0x0025U && message_id <= 0x003aU) ||
        message_id == 0x003cU ||
        message_id == 0x047aU || message_id == 0x0481U ||
        message_id == 0x0482U || message_id == 0x0486U ||
        message_id == 0x0533U || message_id == 0x053dU || message_id == 0x1069U ||
        message_id == 0x0516U || message_id == 0x0547U || message_id == 0x0553U || message_id == 0x04a0U ||
        message_id == 0x05fbU || message_id == 0x3e82U || message_id == 0x06f5U ||
        message_id == 0x0be7U || message_id == 0x0be8U ||
        message_id == 0x10d1U || message_id == 0x1162U ||
        message_id == 0x11d4U || message_id == 0x11d6U ||
        message_id == 0x11d8U || message_id == 0x138cU;
    const bool room_message =
        message_id >= 0x7370U && message_id <= 0x738aU &&
        !IsNoisyMessage(static_cast<std::uint16_t>(message_id));
    const bool trace_dispatch = movement_message || room_message;
    RegisteredHandler handler;
    if (movement_message &&
        !g_movement_handlers_dumped.exchange(true,
                                              std::memory_order_relaxed)) {
            constexpr std::array<unsigned int, 32> kMovementHandlerIds = {
                0x0025U, 0x0027U, 0x0028U, 0x0029U,
                0x002aU, 0x002bU, 0x0034U, 0x0039U,
                0x003aU, 0x047aU, 0x0481U, 0x0482U,
                0x0486U, 0x0516U, 0x0547U, 0x05fbU,
                0x06f5U, 0x0be7U, 0x0be8U, 0x10d1U,
                0x1162U, 0x138cU, 0x3e82U, 0x04a0U,
                0x11d4U, 0x11d6U, 0x11d8U, 0x0038U, 0x003cU,
                0x049dU, 0x74d0U, 0x74cfU};
            const auto image_base =
                g_main_module_base.load(std::memory_order_relaxed);
            for (const auto handler_id : kMovementHandlerIds) {
                const auto registered = FindRegisteredHandler(
                    static_cast<std::uintptr_t>(dispatcher), handler_id);
                const auto callback_rva = registered.callback >= image_base
                    ? registered.callback - image_base
                    : registered.callback;
                const auto registered_name = LookupMessageName(
                    static_cast<std::uint16_t>(handler_id));
                Log("[DISPATCH-TABLE] msg=0x%04X name=%s table=%s "
                    "callback=%p callback_rva=0x%llX context=%p",
                    handler_id,
                    registered_name.empty() ? "<unknown>"
                                            : registered_name.c_str(),
                    registered.table,
                    reinterpret_cast<void*>(registered.callback),
                    static_cast<unsigned long long>(callback_rva),
                    reinterpret_cast<void*>(registered.context));
            }
    }
    if (room_message &&
        !g_room_handlers_dumped.exchange(true, std::memory_order_relaxed)) {
        const auto image_base =
            g_main_module_base.load(std::memory_order_relaxed);
        for (unsigned int handler_id = 0x7370U; handler_id <= 0x738aU;
             ++handler_id) {
            const auto registered = FindRegisteredHandler(
                static_cast<std::uintptr_t>(dispatcher), handler_id);
            const auto callback_rva = registered.callback >= image_base
                ? registered.callback - image_base
                : registered.callback;
            const auto registered_name = LookupMessageName(
                static_cast<std::uint16_t>(handler_id));
            Log("[ROOM-DISPATCH-TABLE] msg=0x%04X name=%s table=%s "
                "callback=%p callback_rva=0x%llX context=%p",
                handler_id,
                registered_name.empty() ? "<unknown>"
                                        : registered_name.c_str(),
                registered.table,
                reinterpret_cast<void*>(registered.callback),
                static_cast<unsigned long long>(callback_rva),
                reinterpret_cast<void*>(registered.context));
        }
    }
    if (trace_dispatch) {
        handler = FindRegisteredHandler(static_cast<std::uintptr_t>(dispatcher),
                                        message_id);
        const auto image_base = g_main_module_base.load(std::memory_order_relaxed);
        const auto callback_rva = handler.callback >= image_base
            ? handler.callback - image_base
            : handler.callback;
        const auto name = LookupMessageName(static_cast<std::uint16_t>(message_id));
        Log("[DISPATCH] phase=before msg=0x%04X name=%s table=%s callback=%p "
            "callback_rva=0x%llX context=%p object=%p native_size=%u hex=%s",
            message_id, name.empty() ? "<unknown>" : name.c_str(), handler.table,
            reinterpret_cast<void*>(handler.callback),
            static_cast<unsigned long long>(callback_rva),
            reinterpret_cast<void*>(handler.context),
            reinterpret_cast<void*>(object), object_size,
            HexBytes(reinterpret_cast<const void*>(object), object_size,
                     kDefaultDumpBytes).c_str());
    }
    if (message_id == 0x737bU) {
        LogRoomUiState("0x737B-dispatch", "before", object, object_size);
    }
    const auto result = g_message_dispatch_hook.unsafe_fastcall<std::int64_t>(
        dispatcher, message_id, object, object_size);
    // Reattached DLLs missed the login-only0x02EF and the initial Actor sync.
    // Recover existing native state on the game thread, without reconnecting.
    if (message_id == 0x1f4aU) RefreshLocalSceneActor();
    if (message_id == 0x0553U && object && object_size >= 33U) {
        const auto native=static_cast<std::uintptr_t>(object);
        const auto rid=RemoteProbeValue<std::uint64_t>(native+4U);
        auto actor=g_scene_actor_pointer.load(std::memory_order_relaxed);
        if (!actor || RemoteProbeValue<std::uint64_t>(actor+40U)!=rid) {
            actor=0;
            std::lock_guard lock(g_remote_probe_mutex);
            for (const auto& entry:g_remote_probes.entries())
                if (entry.rid==rid) { actor=entry.actor; break; }
        }
        const bool identity_ok=actor && RemoteProbeValue<std::uint64_t>(actor+40U)==rid;
        Log("[CHARACTER-SYNC] rid=0x%016llX skin=%u enabled=%u actor=%p identity_ok=%u "
            "flags=%u model=%u presentation=%p",
            static_cast<unsigned long long>(rid),RemoteProbeValue<std::uint32_t>(native+12U),
            unsigned(RemoteProbeValue<std::uint8_t>(native+32U)),reinterpret_cast<void*>(actor),
            unsigned(identity_ok),identity_ok ? unsigned(RemoteProbeValue<std::uint8_t>(actor+104U)) : 0U,
            identity_ok ? RemoteProbeValue<std::uint32_t>(actor+264U) : 0U,
            reinterpret_cast<void*>(identity_ok ? RemoteProbeValue<std::uintptr_t>(actor+48U) : 0U));
    }
    if (message_id==0x0038U) {
        roe::trace_remote::SpecialState special{};
        const bool ok=roe::trace_remote::read_special(
            static_cast<std::uintptr_t>(object),ReadRemoteProbeMemory,special);
        Log("[REMOTE-SPECIAL] native_ok=%u actor=0x%016llX header=%u action=%u clock=%u/%u "
            "relative=%u path=%u auxiliary=%s",
            unsigned(ok),static_cast<unsigned long long>(special.rid),unsigned(special.header),
            unsigned(special.action),special.tick,unsigned(special.fraction),
            unsigned(special.relative_count),special.path,
            HexBytes(special.auxiliary.data(),special.auxiliary_size,16).c_str());
    }
    if (message_id==0x74d0U && object) {
        const auto native=static_cast<std::uintptr_t>(object);
        const auto id=RemoteProbeValue<std::uint64_t>(native+4U);
        const auto owner=RemoteProbeValue<std::uint64_t>(native+12U);
        const auto kind=RemoteProbeValue<std::uint32_t>(native+57U);
        const auto image=g_main_module_base.load(std::memory_order_relaxed);
        std::uintptr_t registry{},entity{};
        const bool registry_ok=roe::trace_remote::read_deployable_registry(
            image,ReadRemoteProbeMemory,registry);
        const bool lookup_ok=registry_ok && roe::trace_remote::find_deployable(
            registry,id,ReadRemoteProbeMemory,entity);
        Log("[BARRIER-CREATE] id=0x%016llX owner=0x%016llX kind=%u state=%u "
            "system=%p registry_ok=%u lookup_ok=%u registry=%p entity=%p",
            static_cast<unsigned long long>(id),static_cast<unsigned long long>(owner),kind,
            kind==1U ? RemoteProbeValue<std::uint32_t>(native+33446U) : 0U,
            reinterpret_cast<void*>(image ? RemoteProbeValue<std::uintptr_t>(
                image+(0x1431C5260ULL-kPreferredImageBase)) : 0U),
            unsigned(registry_ok),unsigned(lookup_ok),reinterpret_cast<void*>(registry),
            reinterpret_cast<void*>(entity));
        if (kind==1U && lookup_ok) {
            { std::lock_guard lock(g_remote_probe_mutex);
              g_deployable_probes.observe(id,entity,GetTickCount64()); }
            LogDeployableSnapshot({id,entity},"dispatch");
        }
    }
    if (message_id==0x74cfU && object) {
        const auto id=RemoteProbeValue<std::uint64_t>(static_cast<std::uintptr_t>(object)+4U);
        std::lock_guard lock(g_remote_probe_mutex);
        g_deployable_probes.erase(id);
    }
    if (message_id == 0x3e82U && object != 0 && object_size >= 22U) {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(object);
        Log("[WEAPON-UPDATE] actor=%llu count=%u slot=%u container=%u "
            "item=%u object_id=%llu mode=%u result=0x%llX",
            static_cast<unsigned long long>(ReadValue<std::uint64_t>(bytes + 41606U)),
            static_cast<unsigned>(ReadValue<std::uint8_t>(bytes + 4U)),
            static_cast<unsigned>(ReadValue<std::uint16_t>(bytes + 5U)),
            static_cast<unsigned>(ReadValue<std::uint8_t>(bytes + 7U)),
            ReadValue<std::uint32_t>(bytes + 10U),
            static_cast<unsigned long long>(ReadValue<std::uint64_t>(bytes + 14U)),
            static_cast<unsigned>(ReadValue<std::uint8_t>(bytes + 41605U)),
            static_cast<unsigned long long>(result));
    }
    if (message_id == 0x04a0U && object != 0 && object_size >= 24U) {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(object);
        Log("[WEAPON-AMMO] actor=%llu slot=%u loaded=%u event=%u result=0x%llX",
            static_cast<unsigned long long>(ReadValue<std::uint64_t>(bytes + 4U)),
            ReadValue<std::uint32_t>(bytes + 12U),
            ReadValue<std::uint32_t>(bytes + 16U),
            ReadValue<std::uint32_t>(bytes + 20U),
            static_cast<unsigned long long>(result));
    }
    if (message_id == 0x1162U && object != 0 && object_size >= 28U) {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(object);
        const auto actor = ReadValue<std::uint64_t>(bytes + 4U);
        const auto count = ReadValue<std::uint32_t>(bytes + 12U);
        for (std::uint32_t index = 0U; index < (std::min)(count, 9U); ++index) {
            const auto* entry = bytes + 16U + index * 12U;
            const auto type = ReadValue<std::uint32_t>(entry);
            const auto local_actor = g_scene_actor_pointer.load(std::memory_order_relaxed);
            const auto policy = local_actor != 0U &&
                    ReadValue<std::uint64_t>(reinterpret_cast<const void*>(local_actor + 40U)) == actor
                ? ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(local_actor + 4240U)) : 0U;
            const auto grapple_remaining = type == 1U && policy != 0U
                ? ReadValue<std::uint32_t>(reinterpret_cast<const void*>(policy + 1972U)) : 0U;
            Log("[ABILITY-CHARGES] actor=%llu type=%u remaining=%u cooldown_ms=%u "
                "grapple_local_remaining=%u result=0x%llX",
                static_cast<unsigned long long>(actor), type,
                ReadValue<std::uint32_t>(entry + 4U), ReadValue<std::uint32_t>(entry + 8U),
                grapple_remaining, static_cast<unsigned long long>(result));
        }
    }
    if (message_id == 0x02efU) {
        const auto candidate =
            g_login_world_actor_rid.load(std::memory_order_acquire);
        const auto state = ReadRoomUiTraceState();
        bool expected = false;
        if (candidate != 0 && state.selected_role == 0 &&
            g_selected_role_setter_hook &&
            g_selected_role_compat_attempted.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
            Log("[LOBBY-ROLE-COMPAT] phase=before candidate=%llu "
                "lobby_common_data=%p selected_role=%llu",
                static_cast<unsigned long long>(candidate),
                reinterpret_cast<void*>(state.lobby_common_data),
                static_cast<unsigned long long>(state.selected_role));
            const auto setter_result =
                g_selected_role_setter_hook.unsafe_fastcall<std::int64_t>(
                    candidate);
            const auto after = ReadRoomUiTraceState();
            Log("[LOBBY-ROLE-COMPAT] phase=after candidate=%llu "
                "selected_role=%llu result=0x%llX",
                static_cast<unsigned long long>(candidate),
                static_cast<unsigned long long>(after.selected_role),
                static_cast<unsigned long long>(setter_result));
        } else if (candidate != 0 && state.selected_role == 0 &&
                   !g_selected_role_setter_hook) {
            Log("[LOBBY-ROLE-COMPAT] skipped candidate=%llu setter_hook=0",
                static_cast<unsigned long long>(candidate));
        }
    }
    if (message_id == 0x737bU) {
        LogRoomUiState("0x737B-dispatch", "after", object, object_size);
    }
    if (message_id == 0x0583U && object_size >= 12U) {
        const auto departed = ReadValue<std::uint64_t>(reinterpret_cast<const void*>(object + 4U));
        std::lock_guard lock(g_remote_probe_mutex);
        g_remote_probes.erase(departed);
    }
    if (trace_dispatch) {
        Log("[DISPATCH] phase=after msg=0x%04X callback=%p result=0x%llX",
            message_id, reinterpret_cast<void*>(handler.callback),
            static_cast<unsigned long long>(result));
    }
    if (movement_message) {
        if (message_id == 0x0025U || message_id == 0x0027U ||
            message_id == 0x002bU || message_id == 0x0038U || message_id == 0x003cU ||
            message_id == 0x0be7U ||
            message_id == 0x0be8U) {
            ProbeMovementActorState(message_id, object, object_size);
        }
    }
    return result;
}

std::int64_t __fastcall HookSelectedRoleSetter(std::uint64_t role_rid) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto before = ReadRoomUiTraceState();
    Log("[LOBBY-ROLE-SETTER] phase=before role=%llu selected_role=%llu",
        static_cast<unsigned long long>(role_rid),
        static_cast<unsigned long long>(before.selected_role));
    const auto result =
        g_selected_role_setter_hook.unsafe_fastcall<std::int64_t>(role_rid);
    const auto after = ReadRoomUiTraceState();
    Log("[LOBBY-ROLE-SETTER] phase=after role=%llu selected_role=%llu "
        "result=0x%llX",
        static_cast<unsigned long long>(role_rid),
        static_cast<unsigned long long>(after.selected_role),
        static_cast<unsigned long long>(result));
    return result;
}

void __fastcall HookRoomListRefresh(std::uintptr_t manager,
                                    const std::uint32_t* page_data) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto page = ReadValue<std::uint32_t>(page_data);
    const auto page_count = ReadValue<std::uint32_t>(page_data + 1);
    const auto room_count = ReadValue<std::uint32_t>(page_data + 2);
    Log("[ROOM-LIST-REFRESH] manager=%p page_data=%p page=%u "
        "page_count=%u room_count=%u",
        reinterpret_cast<void*>(manager), page_data,
        static_cast<unsigned>(page), static_cast<unsigned>(page_count),
        static_cast<unsigned>(room_count));
    g_room_list_refresh_hook.unsafe_fastcall<void>(manager, page_data);
}

std::int64_t __fastcall HookRoomPageSelect() {
    roe::trace_lifecycle::CallbackScope callback_scope;
    LogRoomUiState("RoomPageSelect", "before");
    const auto result =
        g_room_page_select_hook.unsafe_fastcall<std::int64_t>();
    LogRoomUiState("RoomPageSelect", "after");
    return result;
}

std::int64_t __fastcall HookRoomPageRefresh(std::uintptr_t manager) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    LogRoomUiState("RoomPageRefresh", "before");
    Log("[ROOM-PAGE-REFRESH] phase=before manager=%p",
        reinterpret_cast<void*>(manager));
    const auto result =
        g_room_page_refresh_hook.unsafe_fastcall<std::int64_t>(manager);
    Log("[ROOM-PAGE-REFRESH] phase=after manager=%p result=0x%llX",
        reinterpret_cast<void*>(manager),
        static_cast<unsigned long long>(result));
    LogRoomUiState("RoomPageRefresh", "after");
    return result;
}

std::int64_t __fastcall HookActorSetPosition(std::uintptr_t actor,
                                             const float* position) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto local_actor =
        g_scene_actor_pointer.load(std::memory_order_relaxed);
    const bool is_local = local_actor != 0 && actor == local_actor;
    float xyz[3]{};
    const auto occurrence = is_local
        ? g_actor_transform_calls.fetch_add(1, std::memory_order_relaxed) + 1U
        : 0U;
    const auto presentation = is_local
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(actor + 48U))
        : 0U;
    const auto child = presentation != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(presentation + 6832U))
        : 0U;
    const auto previous_child = is_local
        ? g_last_presentation_child.exchange(child, std::memory_order_relaxed)
        : 0U;
    const bool log_transform = is_local &&
        (occurrence <= 16U || (occurrence & (occurrence - 1U)) == 0U ||
         child != previous_child);
    if (log_transform && position != nullptr) {
        CopyReadable(position, xyz, sizeof(xyz));
        Log("[ACTOR-TRANSFORM] n=%u phase=before actor=%p "
            "xyz=(%.3f,%.3f,%.3f) presentation=%p child=%p",
            occurrence, reinterpret_cast<void*>(actor),
            static_cast<double>(xyz[0]),
            static_cast<double>(xyz[1]), static_cast<double>(xyz[2]),
            reinterpret_cast<void*>(presentation),
            reinterpret_cast<void*>(child));
    }
    const auto result =
        g_actor_set_position_hook.unsafe_fastcall<std::int64_t>(actor, position);
    if (!is_local && InterlockedCompareExchange(&g_stopping, 0, 0) == 0) {
        std::lock_guard lock(g_remote_probe_mutex);
        if (g_remote_probes.tracks(actor)) {
            roe::trace_remote::Position input{};
            const bool valid = ReadRemoteProbeMemory(reinterpret_cast<std::uintptr_t>(position), &input, sizeof(input));
            g_remote_probes.transform(actor, input, valid, GetTickCount64());
        }
    }
    if (log_transform) {
        const auto child_after = presentation != 0U
            ? ReadValue<std::uintptr_t>(
                  reinterpret_cast<const void*>(presentation + 6832U))
            : 0U;
        Log("[ACTOR-TRANSFORM] n=%u phase=after actor=%p result=0x%llX "
            "presentation=%p child=%p",
            occurrence, reinterpret_cast<void*>(actor),
            static_cast<unsigned long long>(result),
            reinterpret_cast<void*>(presentation),
            reinterpret_cast<void*>(child_after));
    }
    return result;
}

struct MovementPhysicsSnapshot {
    std::uintptr_t controller = 0;
    std::uintptr_t actor = 0;
    std::uintptr_t state = 0;
    std::uintptr_t state_vtable = 0;
    std::uintptr_t state_begin = 0;
    std::uintptr_t state_apply_position = 0;
    std::uintptr_t state_update = 0;
    std::uintptr_t state_pull_transform = 0;
    std::uintptr_t network = 0;
    std::uint32_t state_index = 0xffffffffU;
    std::uint32_t vehicle_mode = 0;
    std::uint32_t simulation_steps = 0;
    std::uint32_t simulation_blocked = 0;
    std::uint8_t movement_kind = 0;
    std::uint8_t physics_valid = 0;
    std::uint8_t physics_aux = 0;
    std::uint8_t actor_local = 0;
    double x = 0.0;
    double y = 0.0;
    double z = 0.0;
    float motion_x = 0.0F;
    float motion_y = 0.0F;
    float motion_z = 0.0F;
};

MovementPhysicsSnapshot ReadMovementPhysicsSnapshot(std::uintptr_t controller) {
    MovementPhysicsSnapshot snapshot;
    snapshot.controller = controller;
    if (controller == 0U) {
        return snapshot;
    }
    snapshot.actor = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(controller + 784U));
    snapshot.state = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(controller + 520U));
    snapshot.state_vtable = snapshot.state != 0U
        ? ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(snapshot.state))
        : 0U;
    snapshot.state_index = snapshot.state != 0U
        ? ReadValue<std::uint32_t>(
              reinterpret_cast<const void*>(snapshot.state + 16U))
        : 0xffffffffU;
    if (snapshot.state_vtable != 0U) {
        snapshot.state_begin = ReadValue<std::uintptr_t>(
            reinterpret_cast<const void*>(snapshot.state_vtable + 32U));
        snapshot.state_apply_position = ReadValue<std::uintptr_t>(
            reinterpret_cast<const void*>(snapshot.state_vtable + 80U));
        snapshot.state_update = ReadValue<std::uintptr_t>(
            reinterpret_cast<const void*>(snapshot.state_vtable + 184U));
        snapshot.state_pull_transform = ReadValue<std::uintptr_t>(
            reinterpret_cast<const void*>(snapshot.state_vtable + 192U));
    }
    snapshot.network = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(controller + 24U));
    snapshot.movement_kind = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(controller + 16U));
    snapshot.physics_valid = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(controller + 721U));
    snapshot.physics_aux = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(controller + 722U));
    snapshot.x = ReadValue<double>(
        reinterpret_cast<const void*>(controller + 192U));
    snapshot.y = ReadValue<double>(
        reinterpret_cast<const void*>(controller + 200U));
    snapshot.z = ReadValue<double>(
        reinterpret_cast<const void*>(controller + 208U));
    snapshot.motion_x = ReadValue<float>(
        reinterpret_cast<const void*>(controller + 216U));
    snapshot.motion_y = ReadValue<float>(
        reinterpret_cast<const void*>(controller + 220U));
    snapshot.motion_z = ReadValue<float>(
        reinterpret_cast<const void*>(controller + 224U));
    if (snapshot.network != 0U) {
        snapshot.simulation_steps = ReadValue<std::uint32_t>(
            reinterpret_cast<const void*>(snapshot.network + 1204U));
        snapshot.simulation_blocked = ReadValue<std::uint32_t>(
            reinterpret_cast<const void*>(snapshot.network + 1280U));
    }
    if (snapshot.actor != 0U) {
        snapshot.actor_local = ReadValue<std::uint8_t>(
            reinterpret_cast<const void*>(snapshot.actor + 104U)) & 1U;
        snapshot.vehicle_mode = ReadValue<std::uint32_t>(
            reinterpret_cast<const void*>(snapshot.actor + 928U));
    }
    return snapshot;
}

void LogGrappleAnimation(const char* source,std::uintptr_t presentation,
                         unsigned event,int result) {
    const auto animator=RemoteProbeValue<std::uintptr_t>(presentation+5008U);
    roe::trace_remote::AnimationState full{},grapple{};
    const bool full_ok=roe::trace_remote::read_animation_state(animator,218U,ReadRemoteProbeMemory,full);
    const bool grapple_ok=roe::trace_remote::read_animation_state(animator,8030U,ReadRemoteProbeMemory,grapple);
    Log("[GRAPPLE-EVENT] source=%s presentation=%p event=%u handled=%d "
        "full_ok=%u full=%u/%u grapple_ok=%u grapple=%u/%u frame=%u",
        source,reinterpret_cast<void*>(presentation),event,result,unsigned(full_ok),
        unsigned(full.current),unsigned(full.active),unsigned(grapple_ok),
        unsigned(grapple.current),unsigned(grapple.active),grapple.frame);
}

char __fastcall HookPresentationEvent(std::uintptr_t presentation,unsigned event) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const bool observe=!StopRequested() && event>=31U && event<=37U;
    if (observe) LogGrappleAnimation("before",presentation,event,-1);
    const auto result=g_presentation_event_hook.unsafe_fastcall<char>(presentation,event);
    if (observe) LogGrappleAnimation("after",presentation,event,int(result));
    return result;
}

void __fastcall HookMovementPhysicsTick(float* tick_context,
                                        float delta_seconds) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto controller = tick_context != nullptr
        ? ReadValue<std::uintptr_t>(tick_context)
        : 0U;
    const auto before = ReadMovementPhysicsSnapshot(controller);
    g_movement_physics_tick_hook.unsafe_fastcall<void>(tick_context,
                                                       delta_seconds);
    const auto after = ReadMovementPhysicsSnapshot(controller);

    const auto local_actor =
        g_scene_actor_pointer.load(std::memory_order_relaxed);
    if (local_actor == 0U ||
        (before.actor != local_actor && after.actor != local_actor)) {
        return;
    }
    roe::trace_overlay::UpdateCoordinates(after.x, after.y, after.z);

    const auto occurrence =
        g_movement_physics_ticks.fetch_add(1, std::memory_order_relaxed) + 1U;
    auto burst = g_movement_physics_burst.load(std::memory_order_relaxed);
    while (burst != 0U &&
           !g_movement_physics_burst.compare_exchange_weak(
               burst, burst - 1U, std::memory_order_relaxed)) {
    }
    const auto previous_state =
        g_last_movement_state.exchange(after.state, std::memory_order_relaxed);
    const auto previous_index = g_last_movement_state_index.exchange(
        after.state_index, std::memory_order_relaxed);
    const bool state_changed = previous_state != after.state ||
                               previous_index != after.state_index ||
                               before.state != after.state ||
                               before.state_index != after.state_index;
    const bool log_tick = occurrence <= 16U ||
        (occurrence & (occurrence - 1U)) == 0U || burst != 0U ||
        state_changed;
    if (!log_tick) {
        return;
    }

    Log("[MOVEMENT-PHYSICS] n=%u controller=%p actor=%p local=%u "
        "kind=0x%02X state=%p/%u->%p/%u vtable=%p "
        "callbacks=begin:%p/apply:%p/update:%p/pull:%p "
        "vehicle_mode=%u valid=%u/%u simulation=%u blocked=%u dt=%.6f "
        "xyz=(%.3f,%.3f,%.3f)->(%.3f,%.3f,%.3f) "
        "motion=(%.6f,%.6f,%.6f) burst=%u",
        occurrence, reinterpret_cast<void*>(controller),
        reinterpret_cast<void*>(after.actor),
        static_cast<unsigned>(after.actor_local),
        static_cast<unsigned>(after.movement_kind),
        reinterpret_cast<void*>(before.state), before.state_index,
        reinterpret_cast<void*>(after.state), after.state_index,
        reinterpret_cast<void*>(after.state_vtable),
        reinterpret_cast<void*>(after.state_begin),
        reinterpret_cast<void*>(after.state_apply_position),
        reinterpret_cast<void*>(after.state_update),
        reinterpret_cast<void*>(after.state_pull_transform),
        after.vehicle_mode, static_cast<unsigned>(after.physics_valid),
        static_cast<unsigned>(after.physics_aux), after.simulation_steps,
        after.simulation_blocked, static_cast<double>(delta_seconds),
        before.x, before.y, before.z, after.x, after.y, after.z,
        static_cast<double>(after.motion_x),
        static_cast<double>(after.motion_y),
        static_cast<double>(after.motion_z), burst);
}

void __fastcall HookMovementStateAction(std::uintptr_t controller,
                                        int previous_action, int action,
                                        std::uintptr_t action_context) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto before = ReadMovementPhysicsSnapshot(controller);
    const auto context_active = action_context != 0U
        ? ReadValue<std::uint8_t>(
              reinterpret_cast<const void*>(action_context + 464U))
        : 0U;
    const auto context_state = action_context != 0U
        ? ReadValue<std::int32_t>(
              reinterpret_cast<const void*>(action_context + 468U))
        : -1;
    g_movement_state_action_hook.unsafe_fastcall<void>(
        controller, previous_action, action, action_context);
    const auto after = ReadMovementPhysicsSnapshot(controller);

    const auto local_actor =
        g_scene_actor_pointer.load(std::memory_order_relaxed);
    if (local_actor == 0U ||
        (before.actor != local_actor && after.actor != local_actor)) {
        return;
    }
    static std::atomic<std::uint32_t> occurrences{};
    const auto occurrence =
        occurrences.fetch_add(1, std::memory_order_relaxed) + 1U;
    g_movement_physics_burst.store(12U, std::memory_order_relaxed);
    Log("[MOVEMENT-ACTION] n=%u controller=%p actor=%p prev=%d action=%d "
        "context=%p active=%u context_state=%d kind=0x%02X "
        "state=%p/%u->%p/%u vehicle_mode=%u valid=%u/%u "
        "xyz=(%.3f,%.3f,%.3f) motion=(%.6f,%.6f,%.6f)",
        occurrence, reinterpret_cast<void*>(controller),
        reinterpret_cast<void*>(after.actor), previous_action, action,
        reinterpret_cast<void*>(action_context),
        static_cast<unsigned>(context_active), context_state,
        static_cast<unsigned>(after.movement_kind),
        reinterpret_cast<void*>(before.state), before.state_index,
        reinterpret_cast<void*>(after.state), after.state_index,
        after.vehicle_mode, static_cast<unsigned>(after.physics_valid),
        static_cast<unsigned>(after.physics_aux), after.x, after.y, after.z,
        static_cast<double>(after.motion_x),
        static_cast<double>(after.motion_y),
        static_cast<double>(after.motion_z));
}

float* __fastcall HookMovementSpeedLimits(
    std::uintptr_t movement_config, std::uintptr_t actor,
    unsigned int primary_mode, unsigned int secondary_mode,
    std::uint8_t special_a, std::uint8_t special_b, float* forward,
    float* side, float* backward) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    auto* result = g_movement_speed_limits_hook.unsafe_fastcall<float*>(
        movement_config, actor, primary_mode, secondary_mode, special_a,
        special_b, forward, side, backward);

    const auto local_actor =
        g_scene_actor_pointer.load(std::memory_order_relaxed);
    if (local_actor == 0U || actor != local_actor ||
        g_speed_limits_logged.exchange(true, std::memory_order_relaxed)) {
        return result;
    }

    const auto resource_id = ReadValue<std::uint64_t>(
        reinterpret_cast<const void*>(actor + 40U));
    const auto actor_mode = ReadValue<std::uint32_t>(
        reinterpret_cast<const void*>(actor + 272U));
    const auto global_cap = movement_config != 0U
        ? ReadValue<float>(
              reinterpret_cast<const void*>(movement_config + 208U))
        : 0.0F;
    const auto image_base =
        g_main_module_base.load(std::memory_order_relaxed);
    std::uintptr_t actor_resource = 0U;
    bool lookup_signature_valid = false;
    if (image_base != 0U) {
        const auto lookup_target = image_base +
            (kActorResourceLookupVa - kPreferredImageBase);
        lookup_signature_valid = MatchesPattern(
            reinterpret_cast<const void*>(lookup_target),
            kActorResourceLookupSignature);
        if (lookup_signature_valid) {
            actor_resource = reinterpret_cast<ActorResourceLookupFn>(
                lookup_target)(1U, resource_id);
        } else if (!g_actor_resource_lookup_signature_failed.exchange(
                       true, std::memory_order_relaxed)) {
            Log("[SPEED-LIMITS] resource-lookup-signature-mismatch target=%p",
                reinterpret_cast<void*>(lookup_target));
        }
    }

    const auto forward_value = forward != nullptr ? *forward : 0.0F;
    const auto side_value = side != nullptr ? *side : 0.0F;
    const auto backward_value = backward != nullptr ? *backward : 0.0F;
    Log("[SPEED-LIMITS] actor=%p resource_id=0x%016llX resource=%p "
        "lookup_signature=%u movement_config=%p global_cap=%.6f "
        "modes=%u/%u special=%u/%u actor_mode=%u "
        "result=(forward=%.6f,side=%.6f,backward=%.6f) "
        "resource_300_709=%s",
        reinterpret_cast<void*>(actor),
        static_cast<unsigned long long>(resource_id),
        reinterpret_cast<void*>(actor_resource),
        static_cast<unsigned>(lookup_signature_valid),
        reinterpret_cast<void*>(movement_config),
        static_cast<double>(global_cap), primary_mode, secondary_mode,
        static_cast<unsigned>(special_a), static_cast<unsigned>(special_b),
        actor_mode, static_cast<double>(forward_value),
        static_cast<double>(side_value), static_cast<double>(backward_value),
        actor_resource != 0U
            ? HexBytes(reinterpret_cast<const void*>(actor_resource + 300U),
                       410U, 410U).c_str()
            : "");
    return result;
}

void MaybeRecalculateGroundSpeeds(std::uintptr_t actor,
                                  std::uint8_t input_mask) {
    if (!RecalculateGroundSpeedsEnabled() || actor == 0U ||
        (input_mask & 0x0fU) == 0U) {
        return;
    }
    const auto local_actor =
        g_scene_actor_pointer.load(std::memory_order_relaxed);
    if (local_actor == 0U || actor != local_actor) {
        return;
    }

    const auto forward_before = ReadValue<float>(
        reinterpret_cast<const void*>(actor + 244U));
    const auto backward_before = ReadValue<float>(
        reinterpret_cast<const void*>(actor + 252U));
    const auto side_before = ReadValue<float>(
        reinterpret_cast<const void*>(actor + 260U));
    if (forward_before != 0.0F || backward_before != 0.0F ||
        side_before != 0.0F ||
        g_ground_speed_recalc_attempted.exchange(
            true, std::memory_order_relaxed)) {
        return;
    }

    const auto image_base =
        g_main_module_base.load(std::memory_order_relaxed);
    if (image_base == 0U) {
        Log("[GROUND-SPEED-RECALC] status=no-image-base actor=%p",
            reinterpret_cast<void*>(actor));
        return;
    }
    const auto target = image_base +
        (kActorRecalculateGroundSpeedsVa - kPreferredImageBase);
    if (!MatchesPattern(reinterpret_cast<const void*>(target),
                        kActorRecalculateGroundSpeedsSignature)) {
        if (!g_ground_speed_recalc_signature_failed.exchange(
                true, std::memory_order_relaxed)) {
            Log("[GROUND-SPEED-RECALC] status=signature-mismatch "
                "target=%p actor=%p",
                reinterpret_cast<void*>(target),
                reinterpret_cast<void*>(actor));
        }
        return;
    }

    const auto result =
        reinterpret_cast<ActorRecalculateGroundSpeedsFn>(target)(actor);
    const auto forward_after = ReadValue<float>(
        reinterpret_cast<const void*>(actor + 244U));
    const auto backward_after = ReadValue<float>(
        reinterpret_cast<const void*>(actor + 252U));
    const auto side_after = ReadValue<float>(
        reinterpret_cast<const void*>(actor + 260U));
    Log("[GROUND-SPEED-RECALC] status=called actor=%p target=%p "
        "result=0x%llX input=0x%02X speeds=(%.6f,%.6f,%.6f)->"
        "(%.6f,%.6f,%.6f)",
        reinterpret_cast<void*>(actor), reinterpret_cast<void*>(target),
        static_cast<unsigned long long>(result),
        static_cast<unsigned>(input_mask),
        static_cast<double>(forward_before),
        static_cast<double>(backward_before), static_cast<double>(side_before),
        static_cast<double>(forward_after),
        static_cast<double>(backward_after), static_cast<double>(side_after));
}

std::uint8_t __fastcall HookGroundMovementUpdate(
    std::uintptr_t state, const std::uint8_t* input, std::uintptr_t current,
    float delta_seconds, std::uint8_t gate, std::uint8_t substep,
    std::uintptr_t output) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto input_mask = input != nullptr
        ? ReadValue<std::uint8_t>(input)
        : 0U;
    const auto owner = state != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(state + 8U))
        : 0U;
    const auto actor = owner != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(owner + 312U))
        : 0U;
    const auto movement_aux = owner != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(owner + 328U))
        : 0U;
    MaybeRecalculateGroundSpeeds(actor, input_mask);
    const auto state_flags = state != 0U
        ? ReadValue<std::uint32_t>(
              reinterpret_cast<const void*>(state + 776U))
        : 0U;
    const auto state_scalar = state != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(state + 792U))
        : 0.0F;
    const auto owner_active = owner != 0U
        ? ReadValue<std::uint8_t>(
              reinterpret_cast<const void*>(owner + 539U))
        : 0U;
    const auto result =
        g_ground_movement_update_hook.unsafe_fastcall<std::uint8_t>(
            state, input, current, delta_seconds, gate, substep, output);

    const auto local_actor =
        g_scene_actor_pointer.load(std::memory_order_relaxed);
    if (local_actor == 0U || actor != local_actor) {
        return result;
    }

    static std::atomic<std::uint32_t> occurrences{};
    static std::atomic<std::uint32_t> last_input{0xffffffffU};
    static std::atomic<std::uint32_t> last_flags{0xffffffffU};
    const auto occurrence =
        occurrences.fetch_add(1, std::memory_order_relaxed) + 1U;
    const auto previous_input =
        last_input.exchange(input_mask, std::memory_order_relaxed);
    const auto previous_flags =
        last_flags.exchange(state_flags, std::memory_order_relaxed);
    const bool log_update = occurrence <= 16U ||
        (occurrence & (occurrence - 1U)) == 0U ||
        previous_input != input_mask || previous_flags != state_flags;
    if (!log_update) {
        return result;
    }

    const auto basis_x = actor != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(actor + 4624U))
        : 0.0F;
    const auto basis_y = actor != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(actor + 4628U))
        : 0.0F;
    const auto tune_forward = actor != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(actor + 244U))
        : 0.0F;
    const auto tune_backward = actor != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(actor + 252U))
        : 0.0F;
    const auto tune_side = actor != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(actor + 260U))
        : 0.0F;
    const auto current_vx = current != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(current + 24U))
        : 0.0F;
    const auto current_vy = current != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(current + 28U))
        : 0.0F;
    const auto current_vz = current != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(current + 32U))
        : 0.0F;
    const auto output_vx = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 24U))
        : 0.0F;
    const auto output_vy = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 28U))
        : 0.0F;
    const auto output_vz = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 32U))
        : 0.0F;
    const auto desired_x = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 196U))
        : 0.0F;
    const auto desired_y = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 200U))
        : 0.0F;
    const auto desired_z = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 204U))
        : 0.0F;
    g_movement_physics_burst.store(12U, std::memory_order_relaxed);
    Log("[GROUND-UPDATE] n=%u state=%p owner=%p actor=%p aux=%p "
        "input=0x%02X low4=0x%X dt=%.6f gate=%u substep=%u result=%u "
        "flags=0x%08X alternate=%u scalar=%.6f owner_active=%u "
        "basis=(%.6f,%.6f) tuning=(%.6f,%.6f,%.6f) "
        "current_v=(%.6f,%.6f,%.6f) output_v=(%.6f,%.6f,%.6f) "
        "desired=(%.6f,%.6f,%.6f)",
        occurrence, reinterpret_cast<void*>(state),
        reinterpret_cast<void*>(owner), reinterpret_cast<void*>(actor),
        reinterpret_cast<void*>(movement_aux),
        static_cast<unsigned>(input_mask),
        static_cast<unsigned>(input_mask & 0x0fU),
        static_cast<double>(delta_seconds), static_cast<unsigned>(gate),
        static_cast<unsigned>(substep), static_cast<unsigned>(result),
        state_flags, static_cast<unsigned>((state_flags & 0x10U) != 0U),
        static_cast<double>(state_scalar), static_cast<unsigned>(owner_active),
        static_cast<double>(basis_x), static_cast<double>(basis_y),
        static_cast<double>(tune_forward), static_cast<double>(tune_backward),
        static_cast<double>(tune_side), static_cast<double>(current_vx),
        static_cast<double>(current_vy), static_cast<double>(current_vz),
        static_cast<double>(output_vx), static_cast<double>(output_vy),
        static_cast<double>(output_vz), static_cast<double>(desired_x),
        static_cast<double>(desired_y), static_cast<double>(desired_z));
    return result;
}

std::uint8_t __fastcall HookAirMovementUpdate(
    std::uintptr_t state, const std::uint8_t* input, std::uintptr_t current,
    float delta_seconds, int mode, std::uint8_t substep,
    std::uintptr_t output) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto input_mask = input != nullptr
        ? ReadValue<std::uint8_t>(input)
        : 0U;
    const auto owner = state != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(state + 8U))
        : 0U;
    const auto actor = owner != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(owner + 312U))
        : 0U;
    const auto physics_owner = owner != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(owner + 320U))
        : 0U;
    const auto physics_subject = physics_owner != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(physics_owner + 784U))
        : 0U;
    const auto physics_local = physics_subject != 0U
        ? ReadValue<std::uint8_t>(
              reinterpret_cast<const void*>(physics_subject + 104U)) & 1U
        : 0U;
    const auto phase_before = state != 0U
        ? ReadValue<std::uint32_t>(
              reinterpret_cast<const void*>(state + 24U))
        : 0U;
    const auto direction_x = state != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(state + 32U))
        : 0.0F;
    const auto direction_y = state != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(state + 36U))
        : 0.0F;
    const auto direction_z = state != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(state + 40U))
        : 0.0F;
    const auto result = g_air_movement_update_hook.unsafe_fastcall<std::uint8_t>(
        state, input, current, delta_seconds, mode, substep, output);

    const auto local_actor =
        g_scene_actor_pointer.load(std::memory_order_relaxed);
    if (local_actor == 0U || actor != local_actor) {
        return result;
    }

    const auto phase_after = state != 0U
        ? ReadValue<std::uint32_t>(
              reinterpret_cast<const void*>(state + 24U))
        : 0U;
    static std::atomic<std::uint32_t> occurrences{};
    static std::atomic<std::uint32_t> last_input{0xffffffffU};
    static std::atomic<std::uint32_t> last_phase{0xffffffffU};
    const auto occurrence =
        occurrences.fetch_add(1, std::memory_order_relaxed) + 1U;
    const auto previous_input =
        last_input.exchange(input_mask, std::memory_order_relaxed);
    const auto previous_phase =
        last_phase.exchange(phase_after, std::memory_order_relaxed);
    const bool log_update = occurrence <= 16U ||
        (occurrence & (occurrence - 1U)) == 0U ||
        previous_input != input_mask || previous_phase != phase_after ||
        phase_before != phase_after;
    if (!log_update) {
        return result;
    }

    const auto elapsed = state != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(state + 56U))
        : 0.0F;
    const auto lift = state != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(state + 60U))
        : 0.0F;
    const auto fall = state != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(state + 64U))
        : 0.0F;
    const auto output_vx = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 24U))
        : 0.0F;
    const auto output_vy = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 28U))
        : 0.0F;
    const auto output_vz = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 32U))
        : 0.0F;
    const auto accel_x = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 184U))
        : 0.0F;
    const auto accel_y = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 188U))
        : 0.0F;
    const auto accel_z = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 192U))
        : 0.0F;
    g_movement_physics_burst.store(12U, std::memory_order_relaxed);
    Log("[AIR-UPDATE] n=%u state=%p owner=%p actor=%p "
        "physics_owner=%p physics_subject=%p local=%u input=0x%02X low4=0x%X "
        "dt=%.6f mode=%d substep=%u result=%u phase=%u->%u "
        "direction=(%.6f,%.6f,%.6f) elapsed=%.6f lift=%.6f fall=%.6f "
        "velocity=(%.6f,%.6f,%.6f) accel=(%.6f,%.6f,%.6f)",
        occurrence, reinterpret_cast<void*>(state),
        reinterpret_cast<void*>(owner), reinterpret_cast<void*>(actor),
        reinterpret_cast<void*>(physics_owner),
        reinterpret_cast<void*>(physics_subject),
        static_cast<unsigned>(physics_local),
        static_cast<unsigned>(input_mask),
        static_cast<unsigned>(input_mask & 0x0fU),
        static_cast<double>(delta_seconds), mode,
        static_cast<unsigned>(substep), static_cast<unsigned>(result),
        phase_before, phase_after, static_cast<double>(direction_x),
        static_cast<double>(direction_y), static_cast<double>(direction_z),
        static_cast<double>(elapsed), static_cast<double>(lift),
        static_cast<double>(fall), static_cast<double>(output_vx),
        static_cast<double>(output_vy), static_cast<double>(output_vz),
        static_cast<double>(accel_x), static_cast<double>(accel_y),
        static_cast<double>(accel_z));
    return result;
}

std::uint8_t __fastcall HookFallingMovementUpdate(
    std::uintptr_t state, const std::uint8_t* input, std::uintptr_t current,
    float delta_seconds, int mode, std::uint8_t substep,
    std::uintptr_t output) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto owner = state != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(state + 8U))
        : 0U;
    const auto actor = owner != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(owner + 312U))
        : 0U;
    const auto physics = owner != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(owner + 328U))
        : 0U;
    const auto current_z = current != 0U
        ? ReadValue<double>(reinterpret_cast<const void*>(current + 16U))
        : 0.0;
    const auto current_vz = current != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(current + 32U))
        : 0.0F;
    const auto result =
        g_falling_movement_update_hook.unsafe_fastcall<std::uint8_t>(
            state, input, current, delta_seconds, mode, substep, output);

    const auto local_actor =
        g_scene_actor_pointer.load(std::memory_order_relaxed);
    if (local_actor == 0U || actor != local_actor) {
        return result;
    }

    const auto output_x = output != 0U
        ? ReadValue<double>(reinterpret_cast<const void*>(output))
        : 0.0;
    const auto output_y = output != 0U
        ? ReadValue<double>(reinterpret_cast<const void*>(output + 8U))
        : 0.0;
    const auto output_z = output != 0U
        ? ReadValue<double>(reinterpret_cast<const void*>(output + 16U))
        : 0.0;
    const auto output_vx = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 24U))
        : 0.0F;
    const auto output_vy = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 28U))
        : 0.0F;
    const auto output_vz = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 32U))
        : 0.0F;
    const auto desired_x = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 196U))
        : 0.0F;
    const auto desired_y = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 200U))
        : 0.0F;
    const auto desired_z = output != 0U
        ? ReadValue<float>(reinterpret_cast<const void*>(output + 204U))
        : 0.0F;
    const auto physics_vtable = physics != 0U
        ? ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(physics))
        : 0U;
    const auto physics_move = physics_vtable != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(physics_vtable + 280U))
        : 0U;
    const auto physics_position = physics_vtable != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(physics_vtable + 232U))
        : 0U;
    const auto physics_shape = physics_vtable != 0U
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(physics_vtable + 192U))
        : 0U;

    static std::atomic<std::uint32_t> occurrences{};
    static std::atomic<int> last_vertical_sign{2};
    const auto occurrence =
        occurrences.fetch_add(1, std::memory_order_relaxed) + 1U;
    const int vertical_sign = output_vz > 0.0F ? 1 : output_vz < 0.0F ? -1 : 0;
    const auto previous_sign =
        last_vertical_sign.exchange(vertical_sign, std::memory_order_relaxed);
    const bool log_update = occurrence <= 16U ||
        (occurrence & (occurrence - 1U)) == 0U ||
        previous_sign != vertical_sign || output_z != current_z;
    if (log_update) {
        g_movement_physics_burst.store(12U, std::memory_order_relaxed);
        Log("[FALL-UPDATE] n=%u state=%p owner=%p actor=%p physics=%p "
            "vtable=%p callbacks=shape:%p/position:%p/move:%p "
            "dt=%.6f mode=%d substep=%u result=%u "
            "z=%.6f->%.6f current_vz=%.6f "
            "output_v=(%.6f,%.6f,%.6f) desired=(%.6f,%.6f,%.6f) "
            "output_xy=(%.6f,%.6f)",
            occurrence, reinterpret_cast<void*>(state),
            reinterpret_cast<void*>(owner), reinterpret_cast<void*>(actor),
            reinterpret_cast<void*>(physics),
            reinterpret_cast<void*>(physics_vtable),
            reinterpret_cast<void*>(physics_shape),
            reinterpret_cast<void*>(physics_position),
            reinterpret_cast<void*>(physics_move),
            static_cast<double>(delta_seconds), mode,
            static_cast<unsigned>(substep), static_cast<unsigned>(result),
            current_z, output_z, static_cast<double>(current_vz),
            static_cast<double>(output_vx), static_cast<double>(output_vy),
            static_cast<double>(output_vz), static_cast<double>(desired_x),
            static_cast<double>(desired_y), static_cast<double>(desired_z),
            output_x, output_y);
    }
    return result;
}

std::int64_t __fastcall HookReqJoinInstance(std::int64_t instance_id) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    Log("[INSTANCE] ReqJoinInstance instance_id=0x%016llX",
        static_cast<unsigned long long>(instance_id));
    return g_req_join_instance_hook.unsafe_fastcall<std::int64_t>(instance_id);
}

void __fastcall HookInstanceNotify(std::int64_t object) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    if (object == 0) {
        Log("[INSTANCE] OnJoinInstanceNotify object=<null>");
    } else {
        const auto* base = reinterpret_cast<const std::uint8_t*>(object);
        Log("[INSTANCE] OnJoinInstanceNotify object=%p instance_id=0x%016llX field24=0x%016llX "
            "field2c=0x%08X hex=%s", base,
            static_cast<unsigned long long>(ReadValue<std::uint64_t>(base + 0x08)),
            static_cast<unsigned long long>(ReadValue<std::uint64_t>(base + 0x24)),
            ReadValue<std::uint32_t>(base + 0x2c), HexBytes(base, 0xc0, 0xc0).c_str());
    }
    g_instance_notify_hook.unsafe_fastcall<void>(object);
}

void __fastcall HookJoinInstanceRsp(std::int64_t object) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    if (object == 0) {
        Log("[INSTANCE] OnJoinInstanceRsp object=<null>");
    } else {
        const auto* base = reinterpret_cast<const std::uint8_t*>(object);
        const auto error = ReadValue<std::uint32_t>(base + 0x04);
        const auto endpoint = ReadCString(base + 0x08, 128);
        Log("[INSTANCE] OnJoinInstanceRsp object=%p error=%u endpoint=\"%s\" "
            "key_a=%s key_b=%s field168=0x%08X field172=0x%08X field176=0x%02X hex=%s",
            base, error, endpoint.c_str(), HexBytes(base + 0x88, 16, 16).c_str(),
            HexBytes(base + 0x98, 16, 16).c_str(), ReadValue<std::uint32_t>(base + 0xa8),
            ReadValue<std::uint32_t>(base + 0xac), ReadValue<std::uint8_t>(base + 0xb0),
            HexBytes(base, 0xc0, 0xc0).c_str());
    }
    g_join_instance_rsp_hook.unsafe_fastcall<void>(object);
}

std::string ReadStartPointEventName(std::int64_t** arguments) {
    if (arguments == nullptr) {
        return "<null>";
    }
    const auto entries = ReadValue<std::uintptr_t>(arguments);
    const auto end = ReadValue<std::uintptr_t>(
        reinterpret_cast<const std::uint8_t*>(arguments) + sizeof(void*));
    if (entries == 0 || end < entries || (end - entries) != 72U) {
        return "<unparsed>";
    }
    auto value = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(entries + 2U * sizeof(void*)));
    if (value == 0) {
        value = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(entries));
    }
    if (value == 0) {
        return "<empty>";
    }
    const auto flags = ReadValue<std::uint32_t>(
        reinterpret_cast<const void*>(value + 24U));
    auto text = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(value + 32U));
    if ((flags & 0x40U) != 0 && text != 0) {
        text = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(text));
    }
    return text != 0 ? ReadCString(reinterpret_cast<const void*>(text), 96U)
                     : "<empty>";
}

void LogStartPointState(const char* source, std::int64_t widget,
                        const char* event_name = nullptr) {
    const auto image_base = g_main_module_base.load(std::memory_order_relaxed);
    if (image_base == 0 || widget == 0) {
        return;
    }
    const auto manager = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
        image_base + (kBornPositionManagerGlobalVa - kPreferredImageBase)));
    const auto scene_context = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
        image_base + (kSceneContextGlobalVa - kPreferredImageBase)));
    const auto scene = scene_context != 0
        ? ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(scene_context + 216U))
        : 0;
    const auto* panel = reinterpret_cast<const std::uint8_t*>(widget);
    const auto manager_ready = manager != 0
        ? ReadValue<std::uint8_t>(reinterpret_cast<const void*>(manager + 152U))
        : 0;
    const auto manager_state = manager != 0
        ? ReadValue<std::int32_t>(reinterpret_cast<const void*>(manager + 296U))
        : -999;
    const auto wait_players = manager != 0
        ? ReadValue<std::int32_t>(reinterpret_cast<const void*>(manager + 480U))
        : -999;
    const auto scene_type = scene != 0
        ? ReadValue<std::int32_t>(reinterpret_cast<const void*>(scene + 48U))
        : -999;
    const auto scene_mode = scene != 0
        ? ReadValue<std::int32_t>(reinterpret_cast<const void*>(scene + 140U))
        : -999;
    const auto panel_phase = ReadValue<std::int32_t>(panel + 904U);
    const auto panel_state = ReadValue<std::int32_t>(panel + 908U);
    const auto hover_x = ReadValue<std::int32_t>(panel + 992U);
    const auto hover_y = ReadValue<std::int32_t>(panel + 996U);
    const auto hover_flags = ReadValue<std::int32_t>(panel + 1000U);
    const auto interaction_locked = ReadValue<std::uint8_t>(panel + 511U);
    const auto teammate_anim_finished = ReadValue<std::uint8_t>(panel + 866U);
    const auto startpoint_completed = ReadValue<std::uint8_t>(panel + 870U);
    Log("[STARTPOINT] source=%s event=%s widget=%p manager=%p ready=%u "
        "manager_state=%d wait_players=%d scene_type=%d scene_mode=%d "
        "panel_phase=%d panel_state=%d hover=%d,%d hover_flags=%d "
        "locked=%u teammate_anim=%u completed=%u",
        source, event_name != nullptr ? event_name : "-", panel,
        reinterpret_cast<const void*>(manager), static_cast<unsigned>(manager_ready),
        manager_state, wait_players, scene_type, scene_mode, panel_phase,
        panel_state, hover_x, hover_y, hover_flags,
        static_cast<unsigned>(interaction_locked),
        static_cast<unsigned>(teammate_anim_finished),
        static_cast<unsigned>(startpoint_completed));
}

std::int64_t __fastcall HookStartPointTick(std::int64_t widget) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto result =
        g_startpoint_tick_hook.unsafe_fastcall<std::int64_t>(widget);
    if (widget == 0) {
        return result;
    }
    const auto image_base = g_main_module_base.load(std::memory_order_relaxed);
    const auto manager = image_base != 0
        ? ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
              image_base + (kBornPositionManagerGlobalVa - kPreferredImageBase)))
        : 0;
    const auto* panel = reinterpret_cast<const std::uint8_t*>(widget);
    const auto manager_state = manager != 0
        ? ReadValue<std::int32_t>(reinterpret_cast<const void*>(manager + 296U))
        : -999;
    const auto panel_phase = ReadValue<std::int32_t>(panel + 904U);
    const auto panel_state = ReadValue<std::int32_t>(panel + 908U);
    const auto hover_x = ReadValue<std::int32_t>(panel + 992U);
    const auto hover_y = ReadValue<std::int32_t>(panel + 996U);
    struct Snapshot {
        std::int64_t widget = 0;
        std::int32_t manager_state = -1000;
        std::int32_t panel_phase = -1000;
        std::int32_t panel_state = -1000;
        std::int32_t hover_x = -1000;
        std::int32_t hover_y = -1000;
    };
    thread_local Snapshot previous{};
    if (previous.widget != widget || previous.manager_state != manager_state ||
        previous.panel_phase != panel_phase || previous.panel_state != panel_state ||
        previous.hover_x != hover_x || previous.hover_y != hover_y) {
        LogStartPointState("tick-change", widget);
        previous = Snapshot{widget, manager_state, panel_phase, panel_state,
                            hover_x, hover_y};
    }
    return result;
}

std::int64_t __fastcall HookStartPointEvent(std::int64_t widget,
                                            std::uint8_t* event,
                                            std::int64_t** arguments) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto name = ReadStartPointEventName(arguments);
    const bool relevant = name == "SET_START_POINT" ||
                          name == "HOVER_WORLD_POSITION" ||
                          name == "MOUSE_CLICK";
    if (relevant) {
        LogStartPointState("event-before", widget, name.c_str());
    }
    const auto result = g_startpoint_event_hook.unsafe_fastcall<std::int64_t>(
        widget, event, arguments);
    if (relevant) {
        LogStartPointState("event-after", widget, name.c_str());
    }
    return result;
}

struct MapInteractionState {
    std::uintptr_t manager = 0;
    std::uintptr_t cursor = 0;
    std::int32_t scene_mode = -999;
    std::int32_t manager_state = -999;
    std::int32_t slot = -999;
    std::int32_t position_type = -999;
    std::int32_t grid_x = -999;
    std::int32_t grid_y_raw = -999;
    float mouse_x = 0.0F;
    float mouse_y = 0.0F;
    float manager_deadline = -999.0F;
    float panel_deadline = -999.0F;
    float selection_lead = -999.0F;
    double current_clock = -999.0;
    std::int32_t panel_countdown = -999;
    std::int32_t lock_duration = -999;
    std::uint8_t locked = 0;
    std::uint8_t enabled = 0;
    std::uint8_t move_disabled = 0;
    std::uint8_t cursor_active = 0;
};

MapInteractionState ReadMapInteractionState(std::int64_t widget) {
    MapInteractionState state{};
    const auto image_base = g_main_module_base.load(std::memory_order_relaxed);
    if (image_base == 0 || widget == 0) {
        return state;
    }
    state.manager = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
        image_base + (kBornPositionManagerGlobalVa - kPreferredImageBase)));
    state.cursor = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
        image_base + (kMapCursorGlobalVa - kPreferredImageBase)));
    const auto scene_context = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
        image_base + (kSceneContextGlobalVa - kPreferredImageBase)));
    const auto scene = scene_context != 0
        ? ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(scene_context + 216U))
        : 0;
    const auto* panel = reinterpret_cast<const std::uint8_t*>(widget);
    state.scene_mode = scene != 0
        ? ReadValue<std::int32_t>(reinterpret_cast<const void*>(scene + 140U))
        : -999;
    state.manager_state = state.manager != 0
        ? ReadValue<std::int32_t>(reinterpret_cast<const void*>(state.manager + 296U))
        : -999;
    state.manager_deadline = state.manager != 0
        ? ReadValue<float>(reinterpret_cast<const void*>(state.manager + 200U))
        : -999.0F;
    state.current_clock = ReadValue<double>(reinterpret_cast<const void*>(
        image_base + (kFrameClockGlobalVa - kPreferredImageBase)));
    state.locked = ReadValue<std::uint8_t>(panel + 511U);
    state.enabled = ReadValue<std::uint8_t>(panel + 898U);
    state.move_disabled = ReadValue<std::uint8_t>(panel + 902U);
    state.slot = ReadValue<std::int32_t>(panel + 968U);
    state.position_type = ReadValue<std::int32_t>(panel + 972U);
    state.panel_deadline = ReadValue<float>(panel + 976U);
    state.panel_countdown = ReadValue<std::int32_t>(panel + 980U);
    state.mouse_x = ReadValue<float>(panel + 1128U);
    state.mouse_y = ReadValue<float>(panel + 1132U);
    const auto config = ReadValue<std::uintptr_t>(panel + 1136U);
    if (config != 0) {
        state.lock_duration = ReadValue<std::int32_t>(
            reinterpret_cast<const void*>(config + 24U));
        state.selection_lead = ReadValue<float>(
            reinterpret_cast<const void*>(config + 28U));
    }
    if (state.cursor != 0) {
        state.cursor_active = ReadValue<std::uint8_t>(
            reinterpret_cast<const void*>(state.cursor + 1757U));
        state.grid_x = ReadValue<std::int32_t>(
            reinterpret_cast<const void*>(state.cursor + 1664U));
        state.grid_y_raw = ReadValue<std::int32_t>(
            reinterpret_cast<const void*>(state.cursor + 1668U));
    }
    return state;
}

std::size_t ReadCallbackArgumentCount(std::int64_t* arguments) {
    if (arguments == nullptr) {
        return 0;
    }
    const auto begin = ReadValue<std::uintptr_t>(arguments);
    const auto end = ReadValue<std::uintptr_t>(arguments + 1);
    if (begin == 0 || end < begin || (end - begin) % 24U != 0) {
        return 0;
    }
    return (end - begin) / 24U;
}

void LogMapInteractionState(const char* source, std::int64_t widget,
                            std::int64_t* arguments, std::int64_t result = 0) {
    const auto state = ReadMapInteractionState(widget);
    Log("[MAP-INPUT] source=%s widget=%p argc=%zu result=%lld manager=%p "
        "manager_state=%d scene_mode=%d locked=%u enabled=%u move_disabled=%u "
        "phase=%d position_type=%d cursor=%p cursor_active=%u grid=%d,%d "
        "grid_y_raw=%d mouse=%.3f,%.3f clock=%.3f manager_deadline=%.3f "
        "panel_deadline=%.3f countdown=%d lock_duration=%d selection_lead=%.3f",
        source, reinterpret_cast<const void*>(widget),
        ReadCallbackArgumentCount(arguments), static_cast<long long>(result),
        reinterpret_cast<const void*>(state.manager), state.manager_state,
        state.scene_mode, static_cast<unsigned>(state.locked),
        static_cast<unsigned>(state.enabled),
        static_cast<unsigned>(state.move_disabled), state.slot,
        state.position_type, reinterpret_cast<const void*>(state.cursor),
        static_cast<unsigned>(state.cursor_active), state.grid_x,
        31 - state.grid_y_raw, state.grid_y_raw, state.mouse_x, state.mouse_y,
        state.current_clock, state.manager_deadline, state.panel_deadline,
        state.panel_countdown, state.lock_duration, state.selection_lead);
}

std::int64_t __fastcall HookMapMouseClick(std::int64_t widget,
                                          std::int64_t* arguments) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    LogMapInteractionState("click-before", widget, arguments);
    const auto result = g_map_mouse_click_hook.unsafe_fastcall<std::int64_t>(
        widget, arguments);
    LogMapInteractionState("click-after", widget, arguments, result);
    return result;
}

std::int64_t __fastcall HookMapMouseMove(std::int64_t widget,
                                         std::int64_t* arguments) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    const auto result = g_map_mouse_move_hook.unsafe_fastcall<std::int64_t>(
        widget, arguments);
    const auto state = ReadMapInteractionState(widget);
    struct Snapshot {
        std::int64_t widget = 0;
        std::int32_t grid_x = -1000;
        std::int32_t grid_y_raw = -1000;
        std::uint8_t enabled = 0xff;
        std::uint8_t move_disabled = 0xff;
        std::uint8_t cursor_active = 0xff;
    };
    thread_local Snapshot previous{};
    if (previous.widget != widget || previous.grid_x != state.grid_x ||
        previous.grid_y_raw != state.grid_y_raw ||
        previous.enabled != state.enabled ||
        previous.move_disabled != state.move_disabled ||
        previous.cursor_active != state.cursor_active) {
        LogMapInteractionState("move-change", widget, arguments, result);
        previous = Snapshot{widget, state.grid_x, state.grid_y_raw, state.enabled,
                            state.move_disabled, state.cursor_active};
    }
    return result;
}

bool MatchesPattern(const void* address, const BytePattern& pattern) {
    if (address == nullptr || pattern.empty()) {
        return false;
    }
    std::vector<std::uint8_t> bytes(pattern.size());
    if (!CopyReadable(address, bytes.data(), bytes.size())) {
        return false;
    }
    for (std::size_t index = 0; index < pattern.size(); ++index) {
        if (pattern[index] >= 0 && bytes[index] != static_cast<std::uint8_t>(pattern[index])) {
            return false;
        }
    }
    return true;
}

std::int64_t CallMovementActorLookup(std::uintptr_t target,
                                     std::uint64_t actor_id) {
#if defined(_MSC_VER)
    __try {
        return reinterpret_cast<MovementActorLookupFn>(target)(actor_id);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
#else
    return reinterpret_cast<MovementActorLookupFn>(target)(actor_id);
#endif
}

void RefreshLocalSceneActor() {
    const auto selected=ReadRoomUiTraceState().selected_role;
    const auto image=g_main_module_base.load(std::memory_order_relaxed);
    if (!selected || !image) return;
    const auto lookup=image+(kMovementActorLookupVa-kPreferredImageBase);
    if (!MatchesPattern(reinterpret_cast<const void*>(lookup),kMovementActorLookupSignature)) return;
    const auto actor=static_cast<std::uintptr_t>(CallMovementActorLookup(lookup,selected));
    roe::trace_remote::LocalActorState state;
    if (!roe::trace_remote::read_local_actor(actor,selected,ReadRemoteProbeMemory,state)) return;
    const auto old_id=g_scene_actor_id.exchange(state.rid,std::memory_order_relaxed);
    const auto old_actor=g_scene_actor_pointer.exchange(actor,std::memory_order_relaxed);
    roe::trace_remote::Position position;
    const bool position_ok=ReadRemotePresentationPosition(state.presentation,position);
    if (position_ok) roe::trace_overlay::UpdateCoordinates(position.x,position.y,position.z);
    if (old_id!=state.rid || old_actor!=actor)
        Log("[LOCAL-ACTOR-RECOVERY] rid=0x%016llX actor=%p position_ok=%u source=validated-native-state",
            static_cast<unsigned long long>(state.rid),reinterpret_cast<void*>(actor),unsigned(position_ok));
}

void ProbeMovementActorState(unsigned int message_id, std::int64_t object,
                             unsigned int object_size) {
    if (object == 0) {
        return;
    }
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(object);
    std::uint64_t actor_id = 0;
    std::uint32_t actor_sync_type = 0;
    if ((message_id == 0x0025U || message_id == 0x0027U ||
         message_id == 0x002bU || message_id==0x0038U ||
         message_id==0x003cU) && object_size >= 12U) {
        actor_id = ReadValue<std::uint64_t>(bytes + 4U);
    } else if (message_id == 0x0be7U && object_size >= 20U) {
        // Native 0x0BE7 layout: inner command +0, sync type +4,
        // Actor count +8, followed by the Actor-id list at +12.
        actor_id = ReadValue<std::uint64_t>(bytes + 12U);
        actor_sync_type = ReadValue<std::uint32_t>(bytes + 4U);
    } else if (message_id == 0x0be8U && object_size >= 25U) {
        actor_id = ReadValue<std::uint64_t>(bytes + 17U);
    }
    if (actor_id == 0) {
        return;
    }

    const auto image_base =
        g_main_module_base.load(std::memory_order_relaxed);
    if (image_base == 0) {
        return;
    }
    const auto lookup_target =
        image_base + (kMovementActorLookupVa - kPreferredImageBase);
    if (!MatchesPattern(reinterpret_cast<const void*>(lookup_target),
                        kMovementActorLookupSignature)) {
        if (!g_movement_actor_signature_failed.exchange(
                true, std::memory_order_relaxed)) {
            Log("[ACTOR-PHYS] lookup-signature-mismatch target=%p actor=0x%016llX",
                reinterpret_cast<void*>(lookup_target),
                static_cast<unsigned long long>(actor_id));
        }
        return;
    }

    const auto actor = static_cast<std::uintptr_t>(
        CallMovementActorLookup(lookup_target, actor_id));
    if (!actor || RemoteProbeValue<std::uint64_t>(actor+40U)!=actor_id) return;
    const bool remote_actor=(RemoteProbeValue<std::uint8_t>(actor+104U)&1U)==0;
    if (!remote_actor) {
        RefreshLocalSceneActor();
        if (g_scene_actor_id.load(std::memory_order_relaxed)!=actor_id) return;
    }
    if (remote_actor) {
        // Read-only observation at the existing post-dispatch boundary. Do
        // not replace the local Actor pointer used by overlay/scanner probes.
        const auto presentation = actor ? ReadValue<std::uintptr_t>(
            reinterpret_cast<const void*>(actor + 48U)) : 0U;
        const auto flags = actor ? ReadValue<std::uint8_t>(
            reinterpret_cast<const void*>(actor + 104U)) : 0U;
        if (message_id == 0x0be7U || message_id == 0x0be8U)
            Log("[REMOTE-ACTOR] msg=0x%04X type=%u rid=0x%016llX actor=%p presentation=%p flags=0x%02X",
            message_id, actor_sync_type, static_cast<unsigned long long>(actor_id),
            reinterpret_cast<void*>(actor), reinterpret_cast<void*>(presentation), flags);
        {
            std::lock_guard lock(g_remote_probe_mutex);
            g_remote_probes.observe(actor_id, actor, GetTickCount64());
        }
        if (message_id == 0x0be7U || message_id == 0x0be8U)
            LogRemoteActorSnapshot({actor_id, actor}, "dispatch", message_id, actor_sync_type);
        if (message_id == 0x0be7U && (actor_sync_type == 1U || actor_sync_type == 3U)) {
            roe::trace_remote::BasicState state{};
            const bool valid = roe::trace_remote::read_basic_state(
                static_cast<std::uintptr_t>(object), ReadRemoteProbeMemory, state) && state.rid == actor_id;
            Log("[REMOTE-STATE] rid=0x%016llX fields_ok=%u wire_size=%u base128=%u model132=%u state176=%u hidden4021=%u skin5139=%u use5159=%u hand4017=%u weapon305=%u weapon_object=0x%016llX",
                static_cast<unsigned long long>(actor_id), unsigned(valid), object_size, state.base, state.model,
                unsigned(state.state), unsigned(state.hidden), state.skin, unsigned(state.use_skin),
                state.hand, state.weapon, static_cast<unsigned long long>(state.weapon_object));
        }
        return;
    }
    static thread_local std::uint32_t occurrence = 0;
    ++occurrence;
    if (occurrence > 64U && (occurrence & (occurrence - 1U)) != 0U) {
        return;
    }
    if (actor == 0) {
        Log("[ACTOR-PHYS] n=%u msg=0x%04X actor_id=0x%016llX lookup=<null>",
            occurrence, message_id,
            static_cast<unsigned long long>(actor_id));
        return;
    }
    g_scene_actor_pointer.store(actor, std::memory_order_relaxed);

    const auto holder = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(actor + 176U));
    const auto slot = holder != 0
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(holder + 48U))
        : 0U;
    const auto movement = slot != 0
        ? ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(slot))
        : 0U;
    const auto owner = movement != 0
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(movement + 784U))
        : 0U;
    // Actor vtable +376 resolves the presentation/engine entity from +48;
    // vtable +384 forwards a float3 position to that entity's vtable +456.
    // Logging both sides distinguishes the replicated movement cache from the
    // object that is actually rendered and participates in world physics.
    const auto actor_vtable = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(actor));
    const auto presentation = ReadValue<std::uintptr_t>(
        reinterpret_cast<const void*>(actor + 48U));
    const auto presentation_vtable = presentation != 0
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(presentation))
        : 0U;
    const auto actor_get_presentation = actor_vtable != 0
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(actor_vtable + 376U))
        : 0U;
    const auto actor_set_position = actor_vtable != 0
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(actor_vtable + 384U))
        : 0U;
    const auto presentation_set_position = presentation_vtable != 0
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(presentation_vtable + 456U))
        : 0U;
    const auto presentation_set_active = presentation_vtable != 0
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(presentation_vtable + 1088U))
        : 0U;
    const auto presentation_flags = presentation != 0
        ? ReadValue<std::uint32_t>(
              reinterpret_cast<const void*>(presentation + 3128U))
        : 0U;
    auto presentation_child = presentation != 0
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(presentation + 6832U))
        : 0U;
    auto presentation_child_vtable = presentation_child != 0
        ? ReadValue<std::uintptr_t>(
              reinterpret_cast<const void*>(presentation_child))
        : 0U;
    auto presentation_child_set_position = presentation_child_vtable != 0
        ? ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
              presentation_child_vtable + 456U))
        : 0U;

    if (message_id == 0x0be7U && actor_sync_type == 3U &&
        presentation != 0U && presentation_child == 0U &&
        ForcePresentationActiveEnabled() &&
        !g_presentation_compat_attempted.exchange(
            true, std::memory_order_relaxed)) {
        const auto expected_set_active =
            image_base + (kPresentationSetActiveVa - kPreferredImageBase);
        if (presentation_set_active == expected_set_active &&
            MatchesPattern(reinterpret_cast<const void*>(
                               presentation_set_active),
                           kPresentationSetActiveSignature)) {
            std::int64_t force_result = 0;
#if defined(_MSC_VER)
            __try {
                force_result = reinterpret_cast<PresentationSetActiveFn>(
                    presentation_set_active)(presentation, 1U);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                force_result = static_cast<std::int64_t>(0x8000000000000001ULL);
            }
#else
            force_result = reinterpret_cast<PresentationSetActiveFn>(
                presentation_set_active)(presentation, 1U);
#endif
            presentation_child = ReadValue<std::uintptr_t>(
                reinterpret_cast<const void*>(presentation + 6832U));
            presentation_child_vtable = presentation_child != 0U
                ? ReadValue<std::uintptr_t>(
                      reinterpret_cast<const void*>(presentation_child))
                : 0U;
            presentation_child_set_position = presentation_child_vtable != 0U
                ? ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(
                      presentation_child_vtable + 456U))
                : 0U;
            Log("[PRESENTATION-COMPAT] actor=%p presentation=%p "
                "active_before=%u set_active=%p result=0x%llX child_after=%p "
                "child_vtable=%p child_set_position=%p",
                reinterpret_cast<void*>(actor),
                reinterpret_cast<void*>(presentation),
                static_cast<unsigned>((presentation_flags & 4U) != 0U),
                reinterpret_cast<void*>(presentation_set_active),
                static_cast<unsigned long long>(force_result),
                reinterpret_cast<void*>(presentation_child),
                reinterpret_cast<void*>(presentation_child_vtable),
                reinterpret_cast<void*>(presentation_child_set_position));
        } else {
            Log("[PRESENTATION-COMPAT] skipped actor=%p presentation=%p "
                "set_active=%p expected=%p signature=%u",
                reinterpret_cast<void*>(actor),
                reinterpret_cast<void*>(presentation),
                reinterpret_cast<void*>(presentation_set_active),
                reinterpret_cast<void*>(expected_set_active),
                static_cast<unsigned>(presentation_set_active != 0U &&
                    MatchesPattern(reinterpret_cast<const void*>(
                                       presentation_set_active),
                                   kPresentationSetActiveSignature)));
        }
    }

    // sub_140FA8300 rejects an Actor only when +269 is nonzero. Zero is the
    // normal valid state, so this is an inactive/deleted marker, not active.
    const auto actor_inactive = ReadValue<std::uint8_t>(
        reinterpret_cast<const void*>(actor + 269U));
    const auto move_sequence = movement != 0
        ? ReadValue<std::uint32_t>(
              reinterpret_cast<const void*>(movement + 100U))
        : 0U;
    const auto move_clock = movement != 0
        ? ReadValue<float>(reinterpret_cast<const void*>(movement + 104U))
        : 0.0F;
    const auto move_x = movement != 0
        ? ReadValue<double>(reinterpret_cast<const void*>(movement + 192U))
        : 0.0;
    const auto move_y = movement != 0
        ? ReadValue<double>(reinterpret_cast<const void*>(movement + 200U))
        : 0.0;
    const auto move_z = movement != 0
        ? ReadValue<double>(reinterpret_cast<const void*>(movement + 208U))
        : 0.0;
    const auto pending_primary = movement != 0
        ? ReadValue<std::uint8_t>(
              reinterpret_cast<const void*>(movement + 248U))
        : 0U;
    const auto pending_secondary = movement != 0
        ? ReadValue<std::uint8_t>(
              reinterpret_cast<const void*>(movement + 280U))
        : 0U;
    const auto owner_flags = owner != 0
        ? ReadValue<std::uint8_t>(reinterpret_cast<const void*>(owner + 104U))
        : 0U;
    const auto owner_inactive = owner != 0
        ? ReadValue<std::uint8_t>(reinterpret_cast<const void*>(owner + 269U))
        : 0U;
    // Actor +928 is initialized to 14 by the constructor and changed by the
    // vehicle get-on path (sub_140B28C30 -> vtable +1048). It is not a generic
    // locomotion/physics activation mode.
    const auto owner_vehicle_mode = owner != 0
        ? ReadValue<std::uint32_t>(
              reinterpret_cast<const void*>(owner + 928U))
        : 0U;

    Log("[ACTOR-PHYS] n=%u msg=0x%04X actor_id=0x%016llX actor=%p "
        "inactive=%u actor_vtable=%p presentation=%p presentation_vtable=%p "
        "actor_get_presentation=%p actor_set_position=%p "
        "presentation_set_position=%p presentation_set_active=%p "
        "presentation_flags=0x%08X presentation_active=%u "
        "presentation_child=%p child_vtable=%p child_set_position=%p "
        "holder=%p slot=%p movement=%p owner=%p "
        "owner_flags=0x%02X local=%u owner_inactive=%u "
        "owner_vehicle_mode=%u "
        "move_seq=%u move_clock=%.3f xyz=(%.3f,%.3f,%.3f) "
        "pending=%u/%u move_state=%s owner_state=%s",
        occurrence, message_id,
        static_cast<unsigned long long>(actor_id),
        reinterpret_cast<void*>(actor), static_cast<unsigned>(actor_inactive),
        reinterpret_cast<void*>(actor_vtable),
        reinterpret_cast<void*>(presentation),
        reinterpret_cast<void*>(presentation_vtable),
        reinterpret_cast<void*>(actor_get_presentation),
        reinterpret_cast<void*>(actor_set_position),
        reinterpret_cast<void*>(presentation_set_position),
        reinterpret_cast<void*>(presentation_set_active), presentation_flags,
        static_cast<unsigned>((presentation_flags & 4U) != 0U),
        reinterpret_cast<void*>(presentation_child),
        reinterpret_cast<void*>(presentation_child_vtable),
        reinterpret_cast<void*>(presentation_child_set_position),
        reinterpret_cast<void*>(holder), reinterpret_cast<void*>(slot),
        reinterpret_cast<void*>(movement), reinterpret_cast<void*>(owner),
        static_cast<unsigned>(owner_flags),
        static_cast<unsigned>(owner_flags & 1U),
        static_cast<unsigned>(owner_inactive), owner_vehicle_mode,
        move_sequence,
        static_cast<double>(move_clock), move_x, move_y, move_z,
        static_cast<unsigned>(pending_primary),
        static_cast<unsigned>(pending_secondary),
        movement != 0
            ? HexBytes(reinterpret_cast<const void*>(movement + 96U), 32U, 32U).c_str()
            : "",
        owner != 0
            ? HexBytes(reinterpret_cast<const void*>(owner + 96U), 32U, 32U).c_str()
            : "");
}

std::vector<std::uintptr_t> FindPatternInModule(HMODULE module, const BytePattern& pattern) {
    std::vector<std::uintptr_t> matches;
    MODULEINFO module_info{};
    if (module == nullptr || pattern.empty() ||
        !GetModuleInformation(GetCurrentProcess(), module, &module_info, sizeof(module_info))) {
        return matches;
    }
    auto cursor = reinterpret_cast<std::uintptr_t>(module_info.lpBaseOfDll);
    const auto image_end = cursor + module_info.SizeOfImage;
    while (cursor < image_end) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info)) != sizeof(info)) {
            break;
        }
        const auto region_begin = std::max(cursor, reinterpret_cast<std::uintptr_t>(info.BaseAddress));
        const auto region_end = std::min(image_end,
            reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize);
        if (info.State == MEM_COMMIT && IsExecutableProtection(info.Protect) &&
            region_end > region_begin && region_end - region_begin >= pattern.size()) {
            for (auto candidate = region_begin; candidate + pattern.size() <= region_end; ++candidate) {
                if (MatchesPattern(reinterpret_cast<const void*>(candidate), pattern)) {
                    matches.push_back(candidate);
                    if (matches.size() == 8) {
                        return matches;
                    }
                }
            }
        }
        cursor = region_end > cursor ? region_end : cursor + 0x1000;
    }
    return matches;
}

template <typename Function>
bool InstallExportHook(const char* name, FARPROC target, Function detour,
                       safetyhook::InlineHook& hook) {
    if (target == nullptr) {
        Log("[HOOK] name=%s status=export-not-found", name);
        return false;
    }
    auto result = safetyhook::InlineHook::create(reinterpret_cast<void*>(target), detour);
    if (!result) {
        Log("[HOOK] name=%s status=failed target=%p safetyhook_error=%u", name, target,
            static_cast<unsigned>(result.error().type));
        return false;
    }
    hook = std::move(*result);
    Log("[HOOK] name=%s status=installed target=%p source=export", name, target);
    return true;
}

template <typename Function>
bool InstallInternalAt(const char* name, std::uintptr_t target, Function detour,
                       safetyhook::InlineHook& hook, const BytePattern& signature,
                       const char* source) {
    if (!MatchesPattern(reinterpret_cast<const void*>(target), signature)) {
        return false;
    }
    auto result = safetyhook::InlineHook::create(reinterpret_cast<void*>(target), detour);
    if (!result) {
        Log("[HOOK] name=%s status=failed target=%p source=%s safetyhook_error=%u", name,
            reinterpret_cast<void*>(target), source, static_cast<unsigned>(result.error().type));
        return false;
    }
    hook = std::move(*result);
    Log("[HOOK] name=%s status=installed target=%p source=%s", name,
        reinterpret_cast<void*>(target), source);
    return true;
}

template <typename Function>
void ResolveInternalHook(HMODULE module, const char* name, std::uintptr_t preferred_va,
                         const BytePattern& signature, Function detour,
                         safetyhook::InlineHook& hook, bool allow_scan) {
    if (hook) {
        return;
    }
    const auto base = reinterpret_cast<std::uintptr_t>(module);
    const auto fixed = base + (preferred_va - kPreferredImageBase);
    if (InstallInternalAt(name, fixed, detour, hook, signature, "unpacked-rva")) {
        return;
    }
    if (!allow_scan) {
        return;
    }
    const auto matches = FindPatternInModule(module, signature);
    if (matches.size() == 1) {
        InstallInternalAt(name, matches.front(), detour, hook, signature, "unpacked-signature");
    } else {
        Log("[HOOK] name=%s status=signature-not-unique matches=%zu fixed=%p", name,
            matches.size(), reinterpret_cast<void*>(fixed));
        for (const auto candidate : matches) {
            Log("[HOOK] name=%s candidate=%p", name, reinterpret_cast<void*>(candidate));
        }
    }
}

bool AllInternalHooksInstalled() {
    return g_internal_send_hook && g_decoded_record_hook && g_message_dispatch_hook &&
           g_req_join_instance_hook &&
           g_instance_notify_hook && g_join_instance_rsp_hook &&
           g_actor_set_position_hook && g_movement_physics_tick_hook &&
           g_movement_state_action_hook && g_ground_movement_update_hook &&
           g_air_movement_update_hook && g_movement_speed_limits_hook &&
           g_falling_movement_update_hook && g_relay_stop_session_hook &&
           g_relay_state_changed_hook && g_force_reconnect_hook &&
           g_gcloud_reconnect_hook && g_room_list_refresh_hook &&
           g_room_page_select_hook && g_room_page_refresh_hook &&
           g_selected_role_setter_hook && g_presentation_event_hook;
}

void ProbeInternalHooks(HMODULE module, bool allow_scan) {
    ResolveInternalHook(module, "InternalSend", kInternalSendVa, kInternalSendSignature,
                        &HookInternalSend, g_internal_send_hook, allow_scan);
    ResolveInternalHook(module, "DecodedRecord", kDecodedRecordVa, kDecodedRecordSignature,
                        &HookDecodedRecord, g_decoded_record_hook, allow_scan);
    ResolveInternalHook(module, "MessageDispatch", kMessageDispatchVa,
                        kMessageDispatchSignature, &HookMessageDispatch,
                        g_message_dispatch_hook, allow_scan);
    ResolveInternalHook(module, "SelectedRoleSetter", kSelectedRoleSetterVa,
                        kSelectedRoleSetterSignature,
                        &HookSelectedRoleSetter,
                        g_selected_role_setter_hook, allow_scan);
    ResolveInternalHook(module, "RoomListRefresh", kRoomListRefreshVa,
                        kRoomListRefreshSignature, &HookRoomListRefresh,
                        g_room_list_refresh_hook, allow_scan);
    ResolveInternalHook(module, "RoomPageSelect", kRoomPageSelectVa,
                        kRoomPageSelectSignature, &HookRoomPageSelect,
                        g_room_page_select_hook, allow_scan);
    ResolveInternalHook(module, "RoomPageRefresh", kRoomPageRefreshVa,
                        kRoomPageRefreshSignature, &HookRoomPageRefresh,
                        g_room_page_refresh_hook, allow_scan);
    ResolveInternalHook(module, "ReqJoinInstance", kReqJoinInstanceVa,
                        kReqJoinInstanceSignature, &HookReqJoinInstance,
                        g_req_join_instance_hook, allow_scan);
    ResolveInternalHook(module, "OnJoinInstanceNotify", kInstanceNotifyVa,
                        kInstanceNotifySignature, &HookInstanceNotify,
                        g_instance_notify_hook, allow_scan);
    ResolveInternalHook(module, "OnJoinInstanceRsp", kJoinInstanceRspVa,
                        kJoinInstanceRspSignature, &HookJoinInstanceRsp,
                        g_join_instance_rsp_hook, allow_scan);
    // Start-point/map-selection UI logging is intentionally disabled. These
    // four detours produced [STARTPOINT]/[MAP-INPUT] diagnostics and are no
    // longer needed for gameplay movement tracing.
    // ResolveInternalHook(module, "StartPointTick", kStartPointTickVa,
    //                     kStartPointTickSignature, &HookStartPointTick,
    //                     g_startpoint_tick_hook, allow_scan);
    // ResolveInternalHook(module, "StartPointEvent", kStartPointEventVa,
    //                     kStartPointEventSignature, &HookStartPointEvent,
    //                     g_startpoint_event_hook, allow_scan);
    // ResolveInternalHook(module, "MapMouseClick", kMapMouseClickVa,
    //                     kMapMouseClickSignature, &HookMapMouseClick,
    //                     g_map_mouse_click_hook, allow_scan);
    // ResolveInternalHook(module, "MapMouseMove", kMapMouseMoveVa,
    //                     kMapMouseMoveSignature, &HookMapMouseMove,
    //                     g_map_mouse_move_hook, allow_scan);
    ResolveInternalHook(module, "ActorSetPosition", kActorSetPositionVa,
                        kActorSetPositionSignature, &HookActorSetPosition,
                        g_actor_set_position_hook, allow_scan);
    ResolveInternalHook(module, "MovementPhysicsTick", kMovementPhysicsTickVa,
                        kMovementPhysicsTickSignature,
                        &HookMovementPhysicsTick,
                        g_movement_physics_tick_hook, allow_scan);
    ResolveInternalHook(module, "PresentationEvent", kPresentationEventVa,
                        kPresentationEventSignature, &HookPresentationEvent,g_presentation_event_hook,allow_scan);
    ResolveInternalHook(module, "MovementStateAction", kMovementStateActionVa,
                        kMovementStateActionSignature,
                        &HookMovementStateAction,
                        g_movement_state_action_hook, allow_scan);
    ResolveInternalHook(module, "GroundMovementUpdate", kGroundMovementUpdateVa,
                        kGroundMovementUpdateSignature,
                        &HookGroundMovementUpdate,
                        g_ground_movement_update_hook, allow_scan);
    ResolveInternalHook(module, "AirMovementUpdate", kAirMovementUpdateVa,
                        kAirMovementUpdateSignature,
                        &HookAirMovementUpdate,
                        g_air_movement_update_hook, allow_scan);
    ResolveInternalHook(module, "MovementSpeedLimits", kMovementSpeedLimitsVa,
                        kMovementSpeedLimitsSignature,
                        &HookMovementSpeedLimits,
                        g_movement_speed_limits_hook, allow_scan);
    ResolveInternalHook(module, "FallingMovementUpdate",
                        kFallingMovementUpdateVa,
                        kFallingMovementUpdateSignature,
                        &HookFallingMovementUpdate,
                        g_falling_movement_update_hook, allow_scan);
    ResolveInternalHook(module, "RelayStopSession", kRelayStopSessionVa,
                        kRelayStopSessionSignature, &HookRelayStopSession,
                        g_relay_stop_session_hook, allow_scan);
    ResolveInternalHook(module, "RelayStateChanged", kRelayStateChangedVa,
                        kRelayStateChangedSignature, &HookRelayStateChanged,
                        g_relay_state_changed_hook, allow_scan);
    ResolveInternalHook(module, "ForceReconnect", kForceReconnectVa,
                        kForceReconnectSignature, &HookForceReconnect,
                        g_force_reconnect_hook, allow_scan);
    ResolveInternalHook(module, "GCloudReconnect", kGCloudReconnectVa,
                        kGCloudReconnectSignature, &HookGCloudReconnect,
                        g_gcloud_reconnect_hook, allow_scan);
}

#ifdef ROE_TRACE_LIFECYCLE_TEST_BUILD
void HookLifecycleMidTarget(safetyhook::Context& context) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    context.rcx+=1U;
}
std::uint32_t __fastcall HookLifecycleTestTarget(std::uint32_t value) {
    roe::trace_lifecycle::CallbackScope callback_scope;
    return g_internal_send_hook.unsafe_fastcall<std::uint32_t>(value) + 1U;
}
#endif

DWORD WINAPI InstallHooks(void*) {
#ifdef ROE_TRACE_LIFECYCLE_TEST_BUILD
    StartLogWriter();
    InstallExportHook("LifecycleTest", GetProcAddress(GetModuleHandleW(nullptr), "TraceTestTarget"),
                      &HookLifecycleTestTarget, g_internal_send_hook);
    g_lifecycle_test_mid_hook=safetyhook::create_mid(
        GetProcAddress(GetModuleHandleW(nullptr),"TraceTestMidTarget"),HookLifecycleMidTarget);
    wchar_t ready_name[96]{};
    std::swprintf(ready_name, std::size(ready_name), L"Local\\ROE.Trace.TestReady.%lu", GetCurrentProcessId());
    if (const auto ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, ready_name)) {
        SetEvent(ready);
        CloseHandle(ready);
    }
    return 0;
#endif
    InitializeConsole();
    StartLogWriter();
    roe::trace_overlay::SetLogCallback(
        [](const char* message) { Log("%s", message); });
    DumpMessageNames();
    wchar_t module_path[2048]{};
    GetModuleFileNameW(nullptr, module_path, static_cast<DWORD>(std::size(module_path)));
    Log("[TRACE] version=2 pid=%lu client=%ls", GetCurrentProcessId(), module_path);
    Log("[TRACE] reference=Europa_Client_tp6_unpacked.exe preferred_base=%p",
        reinterpret_cast<void*>(kPreferredImageBase));
    const bool overlay_hooks = roe::trace_overlay::InstallD3D12Hooks();
    Log("[TRACE] overlay_hooks=%u backend=dx12",
        static_cast<unsigned>(overlay_hooks));

    HMODULE winsock = nullptr;
    for (int attempt = 0; attempt < 120 && !StopRequested(); ++attempt) {
        winsock = GetModuleHandleW(L"ws2_32.dll");
        if (winsock != nullptr) {
            break;
        }
        Sleep(250);
    }
    if (winsock != nullptr && !StopRequested()) {
        InstallExportHook("connect", GetProcAddress(winsock, "connect"), &HookConnect,
                          g_connect_hook);
        InstallExportHook("sendto", GetProcAddress(winsock, "sendto"), &HookSendTo,
                          g_sendto_hook);
        InstallExportHook("recvfrom", GetProcAddress(winsock, "recvfrom"), &HookRecvFrom,
                          g_recvfrom_hook);
    } else {
        Log("[HOOK] winsock status=module-timeout");
    }

    HMODULE main_module = GetModuleHandleW(nullptr);
    if (main_module != nullptr) {
        g_main_module_base.store(reinterpret_cast<std::uintptr_t>(main_module),
                                 std::memory_order_relaxed);
    }
    for (int attempt = 0; attempt < 1200 && !StopRequested(); ++attempt) {
        if (main_module == nullptr) {
            main_module = GetModuleHandleW(nullptr);
            if (main_module != nullptr) {
                g_main_module_base.store(
                    reinterpret_cast<std::uintptr_t>(main_module),
                    std::memory_order_relaxed);
            }
        }
        if (main_module != nullptr) {
            const bool allow_scan = attempt >= 20 && (attempt % 20) == 0;
            ProbeInternalHooks(main_module, allow_scan);
            if (AllInternalHooksInstalled()) {
                Log("[TRACE] ready internal_hooks=22 socket_hooks=%u",
                    static_cast<unsigned>(static_cast<bool>(g_connect_hook)) +
                    static_cast<unsigned>(static_cast<bool>(g_sendto_hook)) +
                    static_cast<unsigned>(static_cast<bool>(g_recvfrom_hook)));
                return 0;
            }
        }
        Sleep(500);
    }
    Log("[TRACE] probe-finished internal_send=%u decoded_record=%u dispatch=%u req_join=%u "
        "notify=%u rsp=%u actor_set_position=%u "
        "movement_physics_tick=%u movement_state_action=%u "
        "ground_movement_update=%u air_movement_update=%u "
        "movement_speed_limits=%u falling_movement_update=%u relay_stop=%u "
        "relay_state=%u force_reconnect=%u gcloud_reconnect=%u "
        "room_list_refresh=%u room_page_select=%u room_page_refresh=%u "
        "selected_role_setter=%u presentation_event=%u",
        static_cast<unsigned>(static_cast<bool>(g_internal_send_hook)),
        static_cast<unsigned>(static_cast<bool>(g_decoded_record_hook)),
        static_cast<unsigned>(static_cast<bool>(g_message_dispatch_hook)),
        static_cast<unsigned>(static_cast<bool>(g_req_join_instance_hook)),
        static_cast<unsigned>(static_cast<bool>(g_instance_notify_hook)),
        static_cast<unsigned>(static_cast<bool>(g_join_instance_rsp_hook)),
        static_cast<unsigned>(static_cast<bool>(g_actor_set_position_hook)),
        static_cast<unsigned>(static_cast<bool>(g_movement_physics_tick_hook)),
        static_cast<unsigned>(static_cast<bool>(g_movement_state_action_hook)),
        static_cast<unsigned>(static_cast<bool>(g_ground_movement_update_hook)),
        static_cast<unsigned>(static_cast<bool>(g_air_movement_update_hook)),
        static_cast<unsigned>(static_cast<bool>(g_movement_speed_limits_hook)),
        static_cast<unsigned>(static_cast<bool>(g_falling_movement_update_hook)),
        static_cast<unsigned>(static_cast<bool>(g_relay_stop_session_hook)),
        static_cast<unsigned>(static_cast<bool>(g_relay_state_changed_hook)),
        static_cast<unsigned>(static_cast<bool>(g_force_reconnect_hook)),
        static_cast<unsigned>(static_cast<bool>(g_gcloud_reconnect_hook)),
        static_cast<unsigned>(static_cast<bool>(g_room_list_refresh_hook)),
        static_cast<unsigned>(static_cast<bool>(g_room_page_select_hook)),
        static_cast<unsigned>(static_cast<bool>(g_room_page_refresh_hook)),
        static_cast<unsigned>(static_cast<bool>(g_selected_role_setter_hook)),
        static_cast<unsigned>(static_cast<bool>(g_presentation_event_hook)));
    return 0;
}

auto TraceHooks() {
    return std::array<safetyhook::InlineHook*, 29>{
        &g_connect_hook, &g_sendto_hook, &g_recvfrom_hook,
        &g_internal_send_hook, &g_decoded_record_hook, &g_message_dispatch_hook,
        &g_req_join_instance_hook, &g_instance_notify_hook, &g_join_instance_rsp_hook,
        &g_startpoint_tick_hook, &g_startpoint_event_hook,
        &g_map_mouse_click_hook, &g_map_mouse_move_hook, &g_actor_set_position_hook,
        &g_movement_physics_tick_hook, &g_movement_state_action_hook,
        &g_ground_movement_update_hook, &g_air_movement_update_hook,
        &g_movement_speed_limits_hook, &g_falling_movement_update_hook,
        &g_relay_stop_session_hook, &g_relay_state_changed_hook,
        &g_force_reconnect_hook, &g_gcloud_reconnect_hook,
        &g_room_list_refresh_hook, &g_room_page_select_hook,
        &g_room_page_refresh_hook, &g_selected_role_setter_hook,
        &g_presentation_event_hook};
}

bool PrepareUnload(HMODULE instance) {
    Log("[UNLOAD] requested; disabling hooks, retaining trampolines until quiescent");
    roe::trace_overlay::Stop();
    bool disabled = true;
#ifdef ROE_TRACE_LIFECYCLE_TEST_BUILD
    if (g_lifecycle_test_mid_hook && !g_lifecycle_test_mid_hook.disable()) disabled=false;
#endif
    for (auto* hook : TraceHooks())
        if (*hook && !hook->disable()) disabled = false;
    if (!roe::trace_overlay::DisableHooksForUnload()) disabled = false;
    if (!disabled) {
        Log("[UNLOAD] retained: hook disable/window-subclass cleanup incomplete");
        return false;
    }
    if (!roe::trace_lifecycle::RemoveSafetyHookHandler()) {
        Log("[UNLOAD] retained: SafetyHook exception handler still registered");
        return false;
    }
    const auto deadline = GetTickCount64() + 5000U;
    while (roe::trace_lifecycle::active_callbacks.load() && GetTickCount64() < deadline)
        Sleep(10U);
    if (roe::trace_lifecycle::active_callbacks.load()) {
        Log("[UNLOAD] retained: active callbacks=%u (possibly blocked recvfrom); retry later",
            roe::trace_lifecycle::active_callbacks.load());
        return false;
    }
    // Wait for GPU work to finish before releasing overlay resources.
    bool overlay_done = false;
    while (!(overlay_done = roe::trace_overlay::FinishShutdown()) && GetTickCount64() < deadline)
        Sleep(20U);
    if (!overlay_done) {
        Log("[UNLOAD] retained: GPU fence not finished");
        return false;
    }
    roe::trace_overlay::SetLogCallback(nullptr);
    Log("[UNLOAD] hooks disabled, WndProc restored, GPU drained; checking thread tails");
    g_log_stopping.store(true);
    g_log_queue_ready.notify_all();
    if (g_log_writer_thread) {
        if (WaitForSingleObject(g_log_writer_thread, 3000U) != WAIT_OBJECT_0) return false;
        CloseHandle(g_log_writer_thread);
        g_log_writer_thread = nullptr;
    }
    g_log_writer_started.store(false);

    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), instance, &info, sizeof(info))) return false;
    std::vector<roe::trace_lifecycle::CodeRange> ranges;
    const auto* base = reinterpret_cast<const std::uint8_t*>(instance);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) && section.VirtualAddress < info.SizeOfImage)
            ranges.push_back({reinterpret_cast<std::uintptr_t>(base + section.VirtualAddress),
                std::min<DWORD>(section.Misc.VirtualSize, info.SizeOfImage - section.VirtualAddress)});
    }
    if (ranges.empty()) return false;
    for (auto* hook : TraceHooks())
        if (*hook) ranges.push_back({hook->trampoline().address(), hook->trampoline().size()});
    roe::trace_lifecycle::AppendSafetyHookCodeRanges(ranges);
    roe::trace_overlay::AppendHookCodeRanges(ranges);
    const auto tail_deadline = GetTickCount64() + 3000U;
    bool quiet = false;
    while (!(quiet = roe::trace_lifecycle::ThreadsOutsideCode(ranges)) && GetTickCount64() < tail_deadline)
        Sleep(20U);
    if (!quiet) {
        Log("[UNLOAD] retained: another thread still references DLL/trampoline or cannot be inspected; retry later");
        return false;
    }
    // Nothing can re-enter the disabled hooks. Keep the disabled trampoline
    // allocations until CRT teardown; reset/destruct now cannot recreate VEH.
    Log("[UNLOAD] ready; releasing DLL reference (no forced thread termination)");
    if (g_log_file != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_log_file);
        CloseHandle(g_log_file);
        g_log_file = INVALID_HANDLE_VALUE;
    }
    if (g_console_output != INVALID_HANDLE_VALUE) {
        CloseHandle(g_console_output);
        g_console_output = INVALID_HANDLE_VALUE;
    }
    if (g_owned_console) FreeConsole();
    return true;
}

void ProbeScannerPulseState() {
    // Observation only. Do not replace a timed held scanner with a fake floor
    // entity. IDA: Actor+4264 tactical scanner, phase+16, pulse flag+536,
    // renderer+544; sub_1410ABD60 starts the local pulse independently of ACK.
    const auto actor = g_scene_actor_pointer.load(std::memory_order_relaxed);
    if (actor == 0U) return;
    const auto component = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(actor + 4264U));
    if (component == 0U || ReadValue<std::uintptr_t>(
            reinterpret_cast<const void*>(component + 8U)) != actor) return;
    const auto phase = ReadValue<std::uint32_t>(reinterpret_cast<const void*>(component + 16U));
    const auto active = ReadValue<std::uint8_t>(reinterpret_cast<const void*>(component + 536U));
    const auto renderer = ReadValue<std::uintptr_t>(reinterpret_cast<const void*>(component + 544U));
    static std::uintptr_t last_actor = 0U;
    static std::uint32_t last_phase = 0U;
    static std::uint8_t last_active = 0U;
    static ULONGLONG last_log = 0U;
    const auto now = GetTickCount64();
    if (actor == last_actor && phase == last_phase && active == last_active &&
        (active == 0U || now - last_log < 500U)) return;
    last_actor = actor; last_phase = phase; last_active = active; last_log = now;
    Log("[SCANNER-PULSE] actor=%p component=%p phase=%u active=%u renderer=%p radius=%g",
        reinterpret_cast<void*>(actor), reinterpret_cast<void*>(component), phase,
        static_cast<unsigned>(active), reinterpret_cast<void*>(renderer),
        renderer != 0U ? static_cast<double>(ReadValue<float>(
            reinterpret_cast<const void*>(renderer + 76U))) : 0.0);
}

bool RunTrace(HMODULE instance) {
    wchar_t event_name[96]{};
    std::swprintf(event_name, std::size(event_name), L"Local\\ROE.Trace.Unload.%lu", GetCurrentProcessId());
    g_unload_event = CreateEventW(nullptr, TRUE, FALSE, event_name);
    InstallHooks(nullptr);
    for (;;) {
        if (StopRequested()) {
            if (g_unload_event) ResetEvent(g_unload_event);
            roe::trace_lifecycle::unload_requested.store(false);
            if (PrepareUnload(instance)) {
                if (g_unload_event) CloseHandle(g_unload_event);
                g_unload_event = nullptr;
                return true;
            }
            // Failed closed: hooks stay disabled; code/trampolines/resources
            // stay mapped. A later explicit request retries cleanup.
            InterlockedExchange(&g_stopping, 0);
        }
        if (InterlockedCompareExchange(&g_stopping, 0, 0) == 0) {
            ProbeScannerPulseState();
            ProbeRemoteActorStates();
        }
        Sleep(100U);
    }
}

DWORD WINAPI TraceWorker(void* parameter) {
    const auto instance = static_cast<HMODULE>(parameter);
    if (RunTrace(instance)) FreeLibraryAndExitThread(instance, 0);
    return 0;
}

} // namespace

extern "C" __declspec(dllexport) DWORD WINAPI RoeTraceRequestUnload(void*) {
    roe::trace_lifecycle::RequestUnload();
    return ERROR_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        const HANDLE thread = CreateThread(nullptr, 0, &TraceWorker, instance, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        InterlockedExchange(&g_stopping, 1);
        roe::trace_overlay::Stop();
        // Dynamic teardown already ran outside the loader lock. Process exit
        // only sets flags: never wait/join/restore code in DllMain.
    }
    return TRUE;
}
