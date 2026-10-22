#pragma once

#include <cstdint>
#include <cstddef>
#include <string_view>

namespace roe {

struct MessageNameEntry {
  std::uint16_t id;
  std::string_view name;
};

// Returns the canonical name registered by the lifted XVersion client.
// An empty view means that the client maps the ID to UnknownMsg_%d.
std::string_view message_name(std::uint16_t message_id) noexcept;
const MessageNameEntry* message_names_data() noexcept;
std::size_t message_names_size() noexcept;

}  // namespace roe
