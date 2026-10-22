#pragma once

#include <vector>
#include "trace_lifecycle.hpp"

namespace roe::trace_overlay {

using LogCallback = void (*)(const char* message);

void SetLogCallback(LogCallback callback);
bool InstallD3D12Hooks();
void UpdateCoordinates(double x, double y, double z);
void Stop();
bool DisableHooksForUnload();
void AppendHookCodeRanges(std::vector<trace_lifecycle::CodeRange>& ranges);
bool FinishShutdown();

} // namespace roe::trace_overlay
