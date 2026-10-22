#pragma once

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace roe::trace_remote {

struct LocalActorState {
    std::uint64_t rid{};
    std::uintptr_t presentation{};
};

// A packet's first Actor can be an observer. Bind the local context only
// when the current selected RID and the native local-owner flag agree.
template <class Reader>
bool read_local_actor(std::uintptr_t actor,std::uint64_t selected,Reader read,
                      LocalActorState& output) {
    constexpr auto max=std::numeric_limits<std::uintptr_t>::max();
    if (!actor || actor>max-105U || !selected) return false;
    LocalActorState value;
    std::uint8_t flags{};
    if (!read(actor+40U,&value.rid,sizeof(value.rid)) || value.rid!=selected ||
        !read(actor+104U,&flags,sizeof(flags)) || !(flags&1U) ||
        !read(actor+48U,&value.presentation,sizeof(value.presentation)) || !value.presentation)
        return false;
    output=value; return true;
}

struct Position {
    float x{}, y{}, z{};
};
static_assert(sizeof(Position) == 12);

struct MotionState {
    Position velocity{};
    std::uint32_t gait{}, backend{};
    std::uint8_t kind{}, input{};
};

// The separate physics backend6 is also used for a grappling remote actor.
// Inspect the state group and animation parameter instead of equating the two.
struct PoseState {
    std::uint32_t state{}, phase{};
    std::int32_t desired{};
    std::uint8_t active{};
    bool animation_ok{};
    float animation91{};
};

// Read-only field equivalent of 140703CA0's float-parameter access.
template <class Reader>
bool read_animation_float(std::uintptr_t animator,unsigned id,Reader read,float& output) {
    constexpr auto max=std::numeric_limits<std::uintptr_t>::max();
    if (!animator || animator>max-88U || id>4096) return false;
    std::uintptr_t resource{},network{},pins{},outputs{},attribute{};
    std::uint16_t index{};
    float value{};
    if (!read(animator+72,&resource,8) || !resource || resource>max-352U-2U*id ||
        !read(resource+352U+2U*id,&index,2) || index==UINT16_MAX ||
        !read(animator+80,&network,8) || !network || network>max-16U ||
        !read(network+8,&pins,8) || !pins || pins>max-40ULL*index-24U ||
        !read(pins+40ULL*index+16,&outputs,8) || !outputs ||
        !read(outputs,&attribute,8) || !attribute || attribute>max-20U ||
        !read(attribute+16,&value,4) || !std::isfinite(value)) return false;
    output=value; return true;
}

template <class Reader>
bool read_pose(std::uintptr_t actor,Reader read,PoseState& output) {
    constexpr auto max=std::numeric_limits<std::uintptr_t>::max();
    if (!actor || actor>max-4256U) return false;
    std::uint32_t selector{},low{},high{};
    std::uint16_t key{};
    std::uintptr_t encoded{},entry{},policy{};
    PoseState value{};
    if (!read(actor+4048,&selector,4) || !read(actor+4052,&key,2) ||
        !read(actor+1184+4U*(selector&255U),&low,4) ||
        !read(actor+2208+4U*((selector>>8)&255U),&high,4) ||
        !read(actor+3232+8U*(std::uint32_t(low+high+653U)%102U),&encoded,8)) return false;
    const auto state=encoded^key;
    if (!state || state>max-1660U || !read(state+1192,&entry,8) || !entry || entry>max-44U ||
        !read(entry+40,&value.state,4) || !read(state+1652,&value.desired,4) ||
        !read(actor+4240,&policy,8) || !policy || policy>max-536U ||
        !read(policy+505,&value.active,1) || !read(policy+532,&value.phase,4)) return false;
    std::uintptr_t presentation{},animator{};
    if (read(actor+48,&presentation,8) && presentation && presentation<=max-5016U &&
        read(presentation+5008,&animator,8))
        value.animation_ok=read_animation_float(animator,91,read,value.animation91);
    output=value; return true;
}

struct AnimationState {
    std::uint32_t frame{};
    std::uint16_t current{UINT16_MAX}, active{UINT16_MAX};
};

// Native type10 state machine, NodeBin semantic39 / attribute type56.
// Reads existing state only; never initializes or updates an animation network.
template <class Reader>
bool read_animation_state(std::uintptr_t animator,std::uint16_t node,Reader read,
                          AnimationState& output) {
    constexpr auto max=std::numeric_limits<std::uintptr_t>::max();
    const auto pointer=[&](std::uintptr_t base,std::size_t offset,std::uintptr_t& value) {
        return base && base<=max-offset-8U && read(base+offset,&value,8) && value;
    };
    std::uintptr_t network{},definition{},nodes{},node_def{},bins{},entry{},attribute{},state_def{},states{};
    std::uint32_t count{},type{}; std::uint16_t id{},semantic{},attribute_type{},state_count{};
    AnimationState value;
    if (!pointer(animator,80,network) || !pointer(network,0,definition) ||
        definition>max-192U || !read(definition+176,&count,4) || count>65535U || node>=count ||
        !pointer(definition,184,nodes) || !pointer(nodes,8ULL*node,node_def) || node_def>max-12U ||
        !read(node_def,&type,4) || type!=10U || !read(node_def+8,&id,2) || id!=node ||
        !pointer(network,8,bins) || !pointer(bins,40ULL*node,entry) ||
        network>max-44U || !read(network+40,&value.frame,4)) return false;
    for (unsigned n=0;n<64;++n) {
        if (entry>max-32U || !read(entry+28,&semantic,2)) return false;
        if (semantic==39U) break;
        if (n==63U || !pointer(entry,0,entry)) return false;
    }
    if (!pointer(entry,8,attribute) || attribute>max-44U ||
        !read(attribute+10,&attribute_type,2) || attribute_type!=56U ||
        !read(attribute+40,&value.current,2)) return false;
    if (value.current!=UINT16_MAX) {
        if (!pointer(attribute,24,state_def) || state_def>max-32U ||
            !read(state_def+18,&state_count,2) || value.current>=state_count ||
            !pointer(state_def,24,states) || states>max-48ULL*value.current-44U ||
            !read(states+48ULL*value.current+42,&value.active,2) || value.active>=count) return false;
    }
    output=value; return true;
}

// 140F5B190 / 140F5AC10. Reads only: never call a backend or alter animation.
template <class Reader>
bool read_motion(std::uintptr_t movement, std::uintptr_t actor, Reader read, MotionState& output) {
    constexpr auto maximum=std::numeric_limits<std::uintptr_t>::max();
    if (!movement || !actor || movement>maximum-792U || actor>maximum-276U) return false;
    std::uintptr_t owner{}, backend{};
    MotionState value{};
    if (!read(movement+784U,&owner,sizeof(owner)) || owner!=actor ||
        !read(movement+16U,&value.kind,sizeof(value.kind)) ||
        !read(movement+184U,&value.input,sizeof(value.input)) ||
        !read(movement+216U,&value.velocity,sizeof(value.velocity)) ||
        !read(movement+520U,&backend,sizeof(backend)) || !backend || backend>maximum-20U ||
        !read(backend+16U,&value.backend,sizeof(value.backend)) ||
        !read(actor+272U,&value.gait,sizeof(value.gait)) ||
        !std::isfinite(value.velocity.x) || !std::isfinite(value.velocity.y) ||
        !std::isfinite(value.velocity.z)) return false;
    output=value;
    return true;
}

struct BasicState {
    std::uint64_t rid{};
    std::uint32_t type{}, base{}, model{}, skin{}, hand{}, weapon{};
    std::uint64_t weapon_object{};
    std::uint8_t state{}, hidden{}, use_skin{};
};

struct SpecialState {
    std::uint64_t rid{};
    std::uint32_t tick{}, path{};
    std::uint16_t header{};
    std::uint8_t action{}, fraction{}, relative_count{}, auxiliary_size{};
    std::array<std::uint8_t,16> auxiliary{};
};

// 140A24770 native layout, not limited by its shorter encoded wire size.
template <class Reader>
bool read_special(std::uintptr_t message, Reader read, SpecialState& output) {
    if (!message || message>std::numeric_limits<std::uintptr_t>::max()-299U) return false;
    std::uint32_t command{};
    SpecialState value{};
    if (!read(message,&command,4) || command!=0x0038 ||
        !read(message+4,&value.rid,8) || !value.rid ||
        !read(message+12,&value.header,2) ||
        !read(message+26,&value.action,1) || !read(message+27,&value.fraction,1) ||
        value.fraction>=40 || !read(message+28,&value.tick,4) ||
        !read(message+32,&value.relative_count,1) || value.relative_count>20 ||
        !read(message+278,&value.path,4) ||
        !read(message+282,&value.auxiliary_size,1) || value.auxiliary_size>16 ||
        (value.auxiliary_size && !read(message+283,value.auxiliary.data(),value.auxiliary_size))) return false;
    output=value;
    return true;
}

// 1410B90D0 uses the deployable registry, NOT Actor/generic RID lookup.
// A successful read with output0 means absent. Cap corrupted/cyclic buckets.
template <class Reader>
bool read_deployable_registry(std::uintptr_t image,Reader read,std::uintptr_t& output) {
    constexpr auto maximum=std::numeric_limits<std::uintptr_t>::max();
    constexpr std::uintptr_t selector_rva=0x3218580,table_rva=0x3217A50;
    if (!image || image>maximum-selector_rva-8U) return false;
    std::uint64_t selector{},encoded{};
    std::uint32_t low{},high{};
    if (!read(image+selector_rva,&selector,8) ||
        !read(image+table_rva+4U*(selector&255U),&low,4) ||
        !read(image+table_rva+1024U+4U*((selector>>8)&255U),&high,4)) return false;
    const auto slot=std::uint32_t(low+high+5807U)%102U;
    if (!read(image+table_rva+2048U+8U*slot,&encoded,8)) return false;
    const auto root=encoded^std::uint16_t(selector>>32);
    std::uintptr_t registry{};
    if (!root || root>maximum-0x16A8U || !read(root+0x16A0U,&registry,8) || !registry) return false;
    output=registry; return true;
}

template <class Reader>
bool find_deployable(std::uintptr_t registry,std::uint64_t rid,Reader read,std::uintptr_t& output) {
    constexpr auto maximum=std::numeric_limits<std::uintptr_t>::max();
    if (!registry || !rid || registry>maximum-76U) return false;
    std::uintptr_t buckets{},node{},sentinel{};
    std::uint32_t count{};
    if (!read(registry+64,&buckets,8) || !read(registry+72,&count,4) ||
        !buckets || !count || count>1048576 || buckets>maximum-8ULL*count ||
        !read(buckets+8ULL*count,&sentinel,8) ||
        !read(buckets+8ULL*(std::uint32_t(rid)%count),&node,8)) return false;
    for (unsigned i=0;i<256;++i) {
        if (!node || node==sentinel) { output=0; return true; }
        if (node>maximum-32U) return false;
        std::uint64_t key{};
        if (!read(node,&key,8)) return false;
        if (key==rid) {
            std::uintptr_t entity{};
            if (!read(node+8,&entity,8)) return false;
            output=entity; return true;
        }
        if (!read(node+24,&node,8)) return false;
    }
    return false;
}

// 140B352B0 consumes fixed-size native arrays, NOT a buffer whose length is
// the dispatch wire_size. Validate the decoded header and each memory read.
template <class Reader>
bool read_basic_state(std::uintptr_t message, Reader read, BasicState& output) {
    if (!message || message > std::numeric_limits<std::uintptr_t>::max() - 5240U) return false;
    std::uint32_t command{}, count{};
    BasicState value{};
    if (!read(message, &command, sizeof(command)) || command != 0x0BE7U ||
        !read(message + 4U, &value.type, sizeof(value.type)) ||
        (value.type != 1U && value.type != 3U) ||
        !read(message + 8U, &count, sizeof(count)) || !count || count > 8U ||
        !read(message + 12U, &value.rid, sizeof(value.rid)) || !value.rid) return false;
    const auto basic = message + 76U;
    if (!read(basic + 128U, &value.base, sizeof(value.base)) ||
        !read(basic + 132U, &value.model, sizeof(value.model)) ||
        !read(basic + 176U, &value.state, sizeof(value.state)) ||
        !read(basic + 305U, &value.weapon, sizeof(value.weapon)) ||
        !read(basic + 309U, &value.weapon_object, sizeof(value.weapon_object)) ||
        !read(basic + 4017U, &value.hand, sizeof(value.hand)) ||
        !read(basic + 4021U, &value.hidden, sizeof(value.hidden)) ||
        !read(basic + 5139U, &value.skin, sizeof(value.skin)) ||
        !read(basic + 5159U, &value.use_skin, sizeof(value.use_skin))) return false;
    output = value;
    return true;
}

// Read-only equivalent of lifted sub_14095A850. Do not call a native getter
// from the trace worker: other presentation vtable slots have side effects.
// Reader must return false for inaccessible memory, not silently supply zero.
template <class Reader>
bool read_position(std::uintptr_t presentation, Reader read, Position& output) {
    constexpr auto maximum = std::numeric_limits<std::uintptr_t>::max();
    if (!presentation || presentation > maximum - 4096U) return false;
    std::uint32_t selector{}, first{}, second{};
    std::uint16_t key{};
    if (!read(presentation + 3104U, &selector, sizeof(selector)) ||
        !read(presentation + 3108U, &key, sizeof(key)) ||
        !read(presentation + 240U + 4U * (selector & 255U), &first, sizeof(first)) ||
        !read(presentation + 1264U + 4U * ((selector >> 8U) & 255U), &second, sizeof(second)))
        return false;
    const auto slot = std::uint32_t(first + second + 314U) % 102U;
    std::uintptr_t encoded{};
    if (!read(presentation + 2288U + 8U * slot, &encoded, sizeof(encoded))) return false;
    const auto transform = encoded ^ key;
    if (!transform || transform > maximum - 288U - sizeof(Position)) return false;
    Position value{};
    if (!read(transform + 288U, &value, sizeof(value)) ||
        !std::isfinite(value.x) || !std::isfinite(value.y) || !std::isfinite(value.z)) return false;
    output = value;
    return true;
}

struct Entry {
    std::uint64_t rid{};
    std::uintptr_t actor{};
    std::uint64_t seen_ms{};
    std::uint64_t transforms{};
    Position last_input{};
    bool input_valid{};
};

// External synchronization belongs to the caller. No native pointer is
// dereferenced here. Worker sampling additionally verifies Actor+40 == RID.
template <std::size_t Capacity = 64>
class Registry {
public:
    static_assert(Capacity > 0);
    static constexpr std::uint64_t lease_ms = 30000;
    void expire(std::uint64_t now) {
        for (auto& e : entries_)
            if (e.rid && now >= e.seen_ms && now - e.seen_ms >= lease_ms) e = {};
    }
    void observe(std::uint64_t rid, std::uintptr_t actor, std::uint64_t now) {
        if (!rid) return;
        expire(now);
        Entry* target = nullptr;
        for (auto& e : entries_) if (e.rid == rid) { target = &e; break; }
        if (!target) for (auto& e : entries_) if (!e.rid) { target = &e; break; }
        if (!target) {
            target = &entries_[0];
            for (auto& e : entries_) if (e.seen_ms < target->seen_ms) target = &e;
        }
        if (target->rid != rid || target->actor != actor) *target = {};
        target->rid = rid; target->actor = actor; target->seen_ms = now;
    }
    void erase(std::uint64_t rid) {
        for (auto& e : entries_) if (e.rid == rid) e = {};
    }
    bool tracks(std::uintptr_t actor) const {
        if (!actor) return false;
        for (const auto& e : entries_) if (e.rid && e.actor == actor) return true;
        return false;
    }
    void transform(std::uintptr_t actor, Position value, bool valid, std::uint64_t now) {
        if (!actor) return;
        for (auto& e : entries_) if (e.rid && e.actor == actor) {
            ++e.transforms; e.last_input = value; e.input_valid = valid; e.seen_ms = now;
            return;
        }
    }
    const auto& entries() const { return entries_; }
private:
    std::array<Entry, Capacity> entries_{};
};
} // namespace roe::trace_remote
