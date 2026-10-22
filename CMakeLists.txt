cmake_minimum_required(VERSION 3.28)
project(roe_trace VERSION 0.1.0 LANGUAGES C CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "roe_trace requires a Windows x64 toolchain")
endif()
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "Use an out-of-source build: cmake -S . -B build")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build bundled dependencies statically" FORCE)

# All dependency sources are included. Configuration never fetches a package.
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYAN_SYSTEM_ZYCORE OFF CACHE BOOL "" FORCE)
set(ZYAN_ZYCORE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/third_party/zydis/dependencies/zycore"
    CACHE PATH "Bundled Zycore sources" FORCE)
add_subdirectory(third_party/zydis EXCLUDE_FROM_ALL)

set(SAFETYHOOK_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_BUILD_MODULE OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_FETCH_ZYDIS OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/safetyhook EXCLUDE_FROM_ALL)

# Preserve the counted VEH implementation used by cooperative DLL unloading.
get_target_property(ROE_SAFETYHOOK_SOURCES safetyhook SOURCES)
list(FILTER ROE_SAFETYHOOK_SOURCES EXCLUDE REGEX "(^|/)os\\.windows\\.cpp$")
set_property(TARGET safetyhook PROPERTY SOURCES ${ROE_SAFETYHOOK_SOURCES})
target_sources(safetyhook PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools/trace_safetyhook_os.cpp")

set(ROE_TRACE_SOURCES
  tools/trace_dll.cpp
  tools/trace_overlay.cpp
  tools/trace_lifecycle.cpp
  src/message_names.cpp
  third_party/imgui/imgui.cpp
  third_party/imgui/imgui_draw.cpp
  third_party/imgui/imgui_tables.cpp
  third_party/imgui/imgui_widgets.cpp
  third_party/imgui/backends/imgui_impl_win32.cpp
  third_party/imgui/backends/imgui_impl_dx12.cpp)

function(configure_trace_library target)
  set_target_properties(${target} PROPERTIES PREFIX "")
  target_compile_definitions(${target} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_include_directories(${target} PRIVATE src third_party/imgui third_party/imgui/backends)
  target_link_libraries(${target} PRIVATE
    safetyhook::safetyhook ws2_32 psapi user32 gdi32 dwmapi d3d12 dxgi d3dcompiler)
  if(MINGW)
    target_link_options(${target} PRIVATE -static -static-libgcc -static-libstdc++)
  endif()
endfunction()

add_library(roe_trace SHARED ${ROE_TRACE_SOURCES})
configure_trace_library(roe_trace)

add_executable(roe_injector tools/injector.cpp)
target_compile_definitions(roe_injector PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
if(MINGW)
  target_link_options(roe_injector PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()

include(CTest)
if(BUILD_TESTING)
  foreach(name remote_probe)
    add_executable(trace_${name}_tests tests/trace_${name}_tests.cpp)
    add_test(NAME trace_${name}_tests COMMAND trace_${name}_tests)
  endforeach()
  add_library(roe_trace_lifecycle_fixture SHARED ${ROE_TRACE_SOURCES})
  configure_trace_library(roe_trace_lifecycle_fixture)
  target_compile_definitions(roe_trace_lifecycle_fixture PRIVATE ROE_TRACE_LIFECYCLE_TEST_BUILD)
  add_executable(trace_lifecycle_tests tests/trace_lifecycle_tests.cpp)
  target_compile_definitions(trace_lifecycle_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  if(MINGW)
    target_link_options(trace_lifecycle_tests PRIVATE -municode -static -static-libgcc -static-libstdc++)
  endif()
  add_test(NAME trace_lifecycle_tests COMMAND trace_lifecycle_tests $<TARGET_FILE:roe_trace_lifecycle_fixture>)
  set_tests_properties(trace_lifecycle_tests PROPERTIES TIMEOUT 45)
endif()
