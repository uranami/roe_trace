#include "../tools/trace_remote_probe.hpp"
#include <cstring>
#include <iostream>
#include <vector>

int main() {
    // Synthetic memory, not a fixture taken from an injected game process.
    std::vector<std::uint8_t> memory(16000);
    const auto put = [&](std::size_t at, const auto& value) {
        std::memcpy(memory.data() + at, &value, sizeof(value));
    };
    const auto read = [&](std::uintptr_t at, void* to, std::size_t size) {
        if (at > memory.size() || size > memory.size() - at) return false;
        std::memcpy(to, memory.data() + at, size); return true;
    };
    const auto check = [](bool ok, const char* name) {
        if (!ok) std::cerr << name << '\n'; return ok;
    };
    // Hot reload can see an observer packet before any owner packet. Never
    // promote it to local identity; failed/unreadable state stays unbound.
    constexpr std::uintptr_t local_actor=128;
    roe::trace_remote::LocalActorState local{};
    put(local_actor+40,std::uint64_t{12345});
    put(local_actor+48,std::uintptr_t{10000});
    put(local_actor+104,std::uint8_t{2});
    if (!check(!roe::trace_remote::read_local_actor(local_actor,12345,read,local),
               "observer cannot become owner after reload")) return 1;
    put(local_actor+104,std::uint8_t{3});
    if (!check(roe::trace_remote::read_local_actor(local_actor,12345,read,local) &&
               local.rid==12345 && local.presentation==10000,"recover current owner")) return 1;
    if (!check(!roe::trace_remote::read_local_actor(local_actor,54321,read,local) &&
               !roe::trace_remote::read_local_actor(local_actor,0,read,local) &&
               !roe::trace_remote::read_local_actor(0,12345,read,local) &&
               !roe::trace_remote::read_local_actor(UINTPTR_MAX,12345,read,local),
               "reject stale identity/null/overflow")) return 1;
    const auto no_identity=[&](std::uintptr_t at,void* to,std::size_t size) {
        return at!=local_actor+40 && read(at,to,size);
    };
    if (!check(!roe::trace_remote::read_local_actor(local_actor,12345,no_identity,local),
               "unreadable identity is not ready")) return 1;
    put(local_actor+48,std::uintptr_t{0});
    if (!check(!roe::trace_remote::read_local_actor(local_actor,12345,read,local),
               "reject missing local presentation")) return 1;
    constexpr std::uintptr_t p = 1024, transform = 10000;
    put(p + 3104, std::uint32_t{0x0403}); put(p + 3108, std::uint16_t{0x12AB});
    // The low-byte table starts at +240, HIGH-byte table at +1264.
    // Poison the former incorrect low-table location to prevent a fixture
    // from duplicating the reader's old common-base error.
    put(p + 240 + 12, std::uint32_t{0xFFFFFFF0});
    put(p + 1264 + 12, std::uint32_t{0x55555555});
    put(p + 1264 + 16, std::uint32_t{33});
    // Unsigned arithmetic wraps before modulo, matching the native getter.
    constexpr auto slot = std::uint32_t(0xFFFFFFF0U + 33U + 314U) % 102U;
    put(p + 2288 + slot * 8, std::uintptr_t{transform ^ 0x12AB});
    put(transform + 288, roe::trace_remote::Position{403932, 268217, 37380});
    roe::trace_remote::Position xyz{};
    if (!check(roe::trace_remote::read_position(p, read, xyz) && xyz.x == 403932 && xyz.z == 37380,
               "obfuscated position decode")) return 1;
    const auto denied = [&](std::uintptr_t at, void* to, std::size_t size) {
        return at != p + 3108 && read(at, to, size);
    };
    if (!check(!roe::trace_remote::read_position(p, denied, xyz), "failed read is not zero")) return 1;
    put(transform + 288, std::numeric_limits<float>::quiet_NaN());
    if (!check(!roe::trace_remote::read_position(p, read, xyz), "reject non-finite position")) return 1;
    if (!check(!roe::trace_remote::read_position(0, read, xyz) &&
               !roe::trace_remote::read_position(std::numeric_limits<std::uintptr_t>::max(), read, xyz),
               "reject null/overflow pointer")) return 1;
    constexpr std::uintptr_t msg = 7000, basic = msg + 76;
    put(msg, std::uint32_t{0x0BE7}); put(msg + 4, std::uint32_t{3});
    put(msg + 8, std::uint32_t{1}); put(msg + 12, std::uint64_t{12345});
    put(basic + 128, std::uint32_t{0}); put(basic + 132, std::uint32_t{101});
    put(basic + 176, std::uint8_t{0}); put(basic + 4021, std::uint8_t{0});
    put(basic + 305, std::uint32_t{10402}); put(basic + 309, std::uint64_t{54321});
    put(basic + 4017, std::uint32_t{1});
    put(basic + 5139, std::uint32_t{9}); put(basic + 5159, std::uint8_t{1});
    roe::trace_remote::BasicState state{};
    if (!check(roe::trace_remote::read_basic_state(msg, read, state) &&
               state.rid == 12345 && state.model == 101 && state.hidden == 0 && state.skin == 9 && state.use_skin == 1 &&
               state.hand == 1 && state.weapon == 10402 && state.weapon_object == 54321,
               "native fields beyond short wire length")) return 1;
    put(basic + 4021, std::uint8_t{1});
    if (!check(roe::trace_remote::read_basic_state(msg, read, state) && state.hidden == 1,
               "hidden permission observation")) return 1;
    put(msg + 4, std::uint32_t{2});
    if (!check(!roe::trace_remote::read_basic_state(msg, read, state), "type2 has no basic object")) return 1;
    put(msg + 4, std::uint32_t{1}); put(msg + 8, std::uint32_t{9});
    if (!check(!roe::trace_remote::read_basic_state(msg, read, state), "invalid native count")) return 1;
    put(msg + 8, std::uint32_t{1});
    const auto blocked_basic = [&](std::uintptr_t at, void* to, std::size_t size) {
        return at != basic + 4021 && read(at, to, size);
    };
    if (!check(!roe::trace_remote::read_basic_state(msg, blocked_basic, state), "unreadable native field")) return 1;
    constexpr std::uintptr_t movement=13000, actor=14200, backend=15000;
    put(movement+784,actor); put(movement+520,backend);
    put(movement+16,std::uint8_t{1}); put(movement+184,std::uint8_t{1});
    put(movement+216,roe::trace_remote::Position{600,-200,0});
    put(actor+272,std::uint32_t{2}); put(backend+16,std::uint32_t{0});
    roe::trace_remote::MotionState motion{};
    if (!check(roe::trace_remote::read_motion(movement,actor,read,motion) &&
        motion.kind==1 && motion.input==1 && motion.gait==2 && motion.backend==0 &&
        motion.velocity.x==600 && motion.velocity.y==-200,"native locomotion observation")) return 1;
    if (!check(!roe::trace_remote::read_motion(movement,actor+1,read,motion),"reject wrong owner")) return 1;
    const auto blocked_motion=[&](std::uintptr_t at,void* to,std::size_t size) {
        return at!=movement+16 && read(at,to,size);
    };
    if (!check(!roe::trace_remote::read_motion(movement,actor,blocked_motion,motion),
        "unreadable motion does not masquerade as idle")) return 1;
    put(movement+216,std::numeric_limits<float>::quiet_NaN());
    if (!check(!roe::trace_remote::read_motion(movement,actor,read,motion),"reject NaN motion")) return 1;
    if (!check(!roe::trace_remote::read_motion(0,actor,read,motion) &&
        !roe::trace_remote::read_motion(std::numeric_limits<std::uintptr_t>::max(),actor,read,motion),
        "reject motion pointer overflow")) return 1;
    constexpr std::uintptr_t special_msg=128;
    put(special_msg,std::uint32_t{0x0038}); put(special_msg+4,std::uint64_t{12345});
    put(special_msg+12,std::uint16_t{0}); put(special_msg+26,std::uint8_t{53});
    put(special_msg+27,std::uint8_t{39}); put(special_msg+28,std::uint32_t{2695});
    put(special_msg+32,std::uint8_t{1}); put(special_msg+278,std::uint32_t{200});
    put(special_msg+282,std::uint8_t{8}); put(special_msg+283,std::uint16_t{6});
    roe::trace_remote::SpecialState special{};
    if (!check(roe::trace_remote::read_special(special_msg,read,special) &&
        special.rid==12345 && special.action==53 && special.tick==2695 &&
        special.path==200 && special.auxiliary_size==8 && special.auxiliary[0]==6,
        "decoded special fields beyond short wire length")) return 1;
    const auto blocked_special=[&](std::uintptr_t at,void* to,std::size_t size) {
        return at!=special_msg+283 && read(at,to,size);
    };
    if (!check(!roe::trace_remote::read_special(special_msg,blocked_special,special),
        "unreadable special auxiliary")) return 1;
    put(special_msg+282,std::uint8_t{17});
    if (!check(!roe::trace_remote::read_special(special_msg,read,special),"bounded special payload")) return 1;
    put(special_msg+282,std::uint8_t{8}); put(special_msg+27,std::uint8_t{40});
    if (!check(!roe::trace_remote::read_special(special_msg,read,special),"special fraction bound")) return 1;

    constexpr std::uintptr_t image=0x10000000,obstacles=1100,buckets=1200,node=1300;
    constexpr std::uintptr_t root=7000;
    constexpr std::uint64_t obstacle_id=0x7100232A00000001ULL;
    const std::uint64_t selector=(std::uint64_t{0x42}<<32)|0x0201;
    const std::uint64_t encoded_root=root^0x42;
    const std::uint32_t first=1,second=2;
    const auto table_slot=(first+second+5807U)%102U;
    put(root+0x16A0,obstacles);
    const auto root_reader=[&](std::uintptr_t at,void* to,std::size_t size) {
        if (at==image+0x3218580 && size==8) { std::memcpy(to,&selector,8); return true; }
        if (at==image+0x3217A50+4 && size==4) { std::memcpy(to,&first,4); return true; }
        if (at==image+0x3217A50+1024+8 && size==4) { std::memcpy(to,&second,4); return true; }
        if (at==image+0x3217A50+2048+8*table_slot && size==8) { std::memcpy(to,&encoded_root,8); return true; }
        return read(at,to,size);
    };
    std::uintptr_t found_registry{},entity{};
    if (!check(roe::trace_remote::read_deployable_registry(image,root_reader,found_registry) &&
        found_registry==obstacles,"native global deployable registry decode")) return 1;
    if (!check(!roe::trace_remote::read_deployable_registry(image,read,found_registry),
        "unreadable globals do not imply valid registry")) return 1;
    put(obstacles+64,buckets); put(obstacles+72,std::uint32_t{2});
    put(buckets+16,std::uintptr_t{0}); put(buckets+8,node);
    put(node,obstacle_id); put(node+8,std::uintptr_t{9000}); put(node+24,std::uintptr_t{0});
    if (!check(roe::trace_remote::find_deployable(obstacles,obstacle_id,read,entity) &&
        entity==9000,"barrier lookup in dedicated registry")) return 1;
    if (!check(roe::trace_remote::find_deployable(obstacles,obstacle_id+2,read,entity) &&
        entity==0,"absent barrier is distinct from failed read")) return 1;
    put(node+24,node);
    if (!check(!roe::trace_remote::find_deployable(obstacles,obstacle_id+2,read,entity),
        "cyclic native registry is bounded")) return 1;
    put(obstacles+72,std::uint32_t{0});
    if (!check(!roe::trace_remote::find_deployable(obstacles,obstacle_id,read,entity),
        "zero bucket count is not divided")) return 1;
    if (!check(!roe::trace_remote::find_deployable(
        std::numeric_limits<std::uintptr_t>::max(),obstacle_id,read,entity),
        "registry address overflow")) return 1;

    constexpr std::uintptr_t pose_actor=4000,pose_state=9000,pose_entry=11000,policy=11500;
    constexpr std::uintptr_t presentation=2000,animator=12500,resource=13000,network=13600;
    constexpr std::uintptr_t pins=13800,outputs=14000,attribute=14100;
    put(pose_actor+4048,std::uint32_t{0x0201}); put(pose_actor+4052,std::uint16_t{0x42});
    put(pose_actor+1184+4,std::uint32_t{2}); put(pose_actor+2208+8,std::uint32_t{1});
    put(pose_actor+3232+8*((2U+1U+653U)%102U),std::uintptr_t{pose_state^0x42});
    put(pose_state+1192,pose_entry); put(pose_entry+40,std::uint32_t{15});
    put(pose_state+1652,std::int32_t{15}); put(pose_actor+4240,policy);
    put(policy+505,std::uint8_t{1}); put(policy+532,std::uint32_t{6});
    put(pose_actor+48,presentation); put(presentation+5008,animator);
    put(animator+72,resource); put(animator+80,network);
    put(resource+352+2*91,std::uint16_t{0}); put(network+8,pins);
    put(pins+16,outputs); put(outputs,attribute); put(attribute+16,2.F);
    roe::trace_remote::PoseState pose{};
    if (!check(roe::trace_remote::read_pose(pose_actor,read,pose) && pose.state==15 &&
        pose.desired==15 && pose.phase==6 && pose.active==1 &&
        pose.animation_ok && pose.animation91==2.F,
        "grapple state group and animation are distinct from physics backend")) return 1;
    const auto blocked_pose=[&](std::uintptr_t at,void* to,std::size_t size) {
        return at!=pose_actor+4052 && read(at,to,size);
    };
    if (!check(!roe::trace_remote::read_pose(pose_actor,blocked_pose,pose),
        "unreadable state key does not report idle")) return 1;
    put(resource+352+2*91,std::uint16_t{UINT16_MAX});
    if (!check(roe::trace_remote::read_pose(pose_actor,read,pose) &&
        pose.state==15 && !pose.animation_ok,"unmapped parameter does not hide valid pose state")) return 1;
    put(resource+352+2*91,std::uint16_t{0});
    put(attribute+16,std::numeric_limits<float>::quiet_NaN());
    float animation_value=3.F;
    if (!check(!roe::trace_remote::read_animation_float(animator,91,read,animation_value) &&
        animation_value==3.F,"invalid parameter does not overwrite output")) return 1;
    if (!check(!roe::trace_remote::read_pose(std::numeric_limits<std::uintptr_t>::max(),read,pose) &&
        !roe::trace_remote::read_animation_float(std::numeric_limits<std::uintptr_t>::max(),91,read,animation_value),
        "pose/animator overflow")) return 1;

    roe::trace_remote::Registry<2> registry;
    registry.observe(1, 100, 100); registry.observe(2, 200, 200);
    if (!check(registry.tracks(100) && !registry.tracks(0) && !registry.tracks(999), "only tracked Actors")) return 1;
    registry.transform(100, {1,2,3}, true, 300);
    if (!check(registry.entries()[0].transforms == 1 && registry.entries()[1].transforms == 0,
               "per-actor input isolation")) return 1;
    registry.observe(1, 101, 400);
    if (!check(!registry.entries()[0].input_valid && !registry.entries()[0].transforms,
               "replacement pointer clears old transform")) return 1;
    registry.observe(3, 300, 500); // bounded eviction of least recently seen RID 2
    if (!check(registry.entries()[1].rid == 3 && !registry.tracks(200), "bounded registry")) return 1;
    registry.transform(200, {4,5,6}, true, 600);
    if (!check(!registry.entries()[1].transforms, "ignore evicted pointer")) return 1;
    registry.erase(1); registry.expire(30500);
    if (!check(!registry.entries()[0].rid && !registry.entries()[1].rid, "leave/expiry")) return 1;
    registry.observe(0, 999, 30600); registry.transform(0, {}, true, 30600);
    if (!check(!registry.entries()[0].rid, "ignore invalid identity")) return 1;
    std::fill(memory.begin(),memory.end(),0);
    constexpr std::uintptr_t def=9000,nodes=7000,node_def=8000,entry=3000;
    constexpr std::uintptr_t state_attribute=4000,state_def=5000,states=6000;
    put(animator+80,network); put(network,def); put(network+8,pins); put(network+40,std::uint32_t{99});
    put(def+176,std::uint32_t{10}); put(def+184,nodes); put(nodes+8*3,node_def);
    put(node_def,std::uint32_t{10}); put(node_def+8,std::uint16_t{3});
    put(pins+40*3,entry); put(entry+28,std::uint16_t{39}); put(entry+8,state_attribute);
    put(state_attribute+10,std::uint16_t{56}); put(state_attribute+24,state_def);
    put(state_attribute+40,std::uint16_t{2}); put(state_def+18,std::uint16_t{4});
    put(state_def+24,states); put(states+48*2+42,std::uint16_t{8});
    roe::trace_remote::AnimationState animation_state;
    if (!check(roe::trace_remote::read_animation_state(animator,3,read,animation_state) &&
        animation_state.frame==99 && animation_state.current==2 && animation_state.active==8,
        "actual native state-machine branch")) return 1;
    const auto blocked_state=[&](std::uintptr_t at,void* to,std::size_t size) {
        return at!=state_attribute+40 && read(at,to,size);
    };
    if (!check(!roe::trace_remote::read_animation_state(animator,3,blocked_state,animation_state) &&
        animation_state.active==8,"failed state read preserves output")) return 1;
    put(state_attribute+40,std::uint16_t{UINT16_MAX});
    if (!check(roe::trace_remote::read_animation_state(animator,3,read,animation_state) &&
        animation_state.active==UINT16_MAX,"initialized but inactive machine")) return 1;
    put(state_attribute+40,std::uint16_t{4});
    if (!check(!roe::trace_remote::read_animation_state(animator,3,read,animation_state),
        "invalid state index")) return 1;
    put(state_attribute+40,std::uint16_t{2}); put(states+48*2+42,std::uint16_t{10});
    if (!check(!roe::trace_remote::read_animation_state(animator,3,read,animation_state),
        "invalid active node")) return 1;
    put(states+48*2+42,std::uint16_t{8}); put(node_def,std::uint32_t{11});
    if (!check(!roe::trace_remote::read_animation_state(animator,3,read,animation_state),
        "non-state-machine semantic does not use state layout")) return 1;
    put(node_def,std::uint32_t{10}); put(entry+28,std::uint16_t{38}); put(entry,entry);
    if (!check(!roe::trace_remote::read_animation_state(animator,3,read,animation_state),
        "cyclic attribute list is bounded")) return 1;
    if (!check(!roe::trace_remote::read_animation_state(0,3,read,animation_state) &&
        !roe::trace_remote::read_animation_state(std::numeric_limits<std::uintptr_t>::max(),3,read,animation_state),
        "animation state pointer overflow")) return 1;
    std::cout << "remote probe reader and bounded tracking passed\n";
}
