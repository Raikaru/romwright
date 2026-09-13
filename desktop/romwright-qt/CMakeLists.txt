cmake_minimum_required(VERSION 3.21)
project(romwright-qt VERSION 0.5 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Concurrent)
find_package(Threads REQUIRED)

include(GNUInstallDirs)

find_program(CARGO_EXECUTABLE cargo REQUIRED)

set(ROMWRIGHT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(RUST_TARGET "${ROMWRIGHT_ROOT}/target/release")
set(RUST_BRIDGE_LIB "${RUST_TARGET}/libromwright_qt_bridge.a")
if(WIN32)
    set(RUST_BRIDGE_LIB "${RUST_TARGET}/romwright_qt_bridge.lib")
endif()
set(CPACK_PACKAGE_NAME "romwright")
set(CPACK_PACKAGE_VENDOR "Romwright")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "JVM-free reverse-engineering workstation")
set(CPACK_PACKAGE_CONTACT "Romwright maintainers")
set(CPACK_RESOURCE_FILE_LICENSE "${ROMWRIGHT_ROOT}/LICENSE")
set(CPACK_GENERATOR "TGZ")
set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

# cxx_build emits the C++ ABI header and the Rust static library together.
# The build dependency runs first, so the generated include tree exists before
# automoc/compilation of the Qt target.
add_custom_target(romwright-rust-bridge ALL
    COMMAND "${CARGO_EXECUTABLE}" build --release -p romwright-qt-bridge
    WORKING_DIRECTORY "${ROMWRIGHT_ROOT}"
    BYPRODUCTS "${RUST_BRIDGE_LIB}"
    COMMENT "Building the Rust Core/CXX bridge"
)

add_executable(romwright-qt
    src/main.cpp
    src/core_bridge.h
    src/core_bridge.cpp
    src/function_table_model.h
    src/function_table_model.cpp
    src/json_util.h
    src/views.h
    src/listing_canvas.h
    src/listing_canvas.cpp
    src/graph_canvas.h
    src/graph_canvas.cpp
    src/decompiler_view.h
    src/decompiler_view.cpp
    src/navigation_controller.h
    src/navigation_controller.cpp
    src/strings_table_model.h
    src/strings_table_model.cpp
    src/theme.h
    src/theme.cpp
    src/hex_canvas.h
    src/hex_canvas.cpp
    src/main_window.h
    src/main_window.cpp
    src/main_window_commands.cpp
    src/functions_dock.h
    src/functions_dock.cpp
    src/decompiler_dock.h
    src/decompiler_dock.cpp
    src/facts_dock.h
    src/facts_dock.cpp
    src/memory_dock.h
    src/memory_dock.cpp
    src/graph_dock.h
    src/graph_dock.cpp
    src/analyst_dock.h
    src/analyst_dock.cpp
    src/types_dock.h
    src/types_dock.cpp
    src/xrefs_dock.h
    src/xrefs_dock.cpp
    src/jobs_dock.h
    src/jobs_dock.cpp
    src/vtables_dock.h
    src/vtables_dock.cpp
    src/gate_runner.h
    src/gate_runner.cpp
)
add_dependencies(romwright-qt romwright-rust-bridge)
target_include_directories(romwright-qt PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
)
target_link_libraries(romwright-qt PRIVATE
    Qt6::Widgets
    Qt6::Concurrent
    "${RUST_BRIDGE_LIB}"
    Threads::Threads
    "${CMAKE_DL_LIBS}"
)
if(WIN32)
    target_link_libraries(romwright-qt PRIVATE ws2_32 bcrypt userenv advapi32 ntdll)
endif()
if(APPLE)
    target_link_libraries(romwright-qt PRIVATE "-framework Security")
endif()

install(TARGETS romwright-qt
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    BUNDLE DESTINATION .
    COMPONENT Runtime
)

include(CPack)
