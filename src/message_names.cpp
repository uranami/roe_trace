#include "message_names.hpp"

#include <algorithm>
#include <iterator>

namespace roe {
namespace {

constexpr MessageNameEntry kMessageNames[] = {
#include "message_names.inc"
};

}  // namespace

std::string_view message_name(std::uint16_t message_id) noexcept {
  const auto found = std::lower_bound(
      std::begin(kMessageNames), std::end(kMessageNames), message_id,
      [](const auto& entry, std::uint16_t id) { return entry.id < id; });
  if (found == std::end(kMessageNames) || found->id != message_id) return {};
  return found->name;
}

const MessageNameEntry* message_names_data() noexcept {
  return kMessageNames;
}

std::size_t message_names_size() noexcept {
  return std::size(kMessageNames);
}

}  // namespace roe
