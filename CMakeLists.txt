cmake_minimum_required(VERSION 3.16)
project(autosar-idsm-toolkit LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Core library: mix of C (AUTOSAR API) and C++ (manager)
add_library(idsm_core STATIC
    src/IdsM.c
    src/IdsM_Manager.cpp
)
target_include_directories(idsm_core PUBLIC include)
target_compile_options(idsm_core PRIVATE -Wall -Wextra -Wpedantic)

# CLI application
add_executable(idsm_cli apps/idsm_cli/main.cpp)
target_link_libraries(idsm_cli PRIVATE idsm_core)

# Install targets
install(TARGETS idsm_core idsm_cli
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include)