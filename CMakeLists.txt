cmake_minimum_required(VERSION 3.16)
project(net_threat_detect C)

# ============================================================================
# Include modular CMake files
# ============================================================================
include(cmake/CompilerOptions.cmake)
include(cmake/SystemChecks.cmake)
include(cmake/ConfigGeneration.cmake)
include(cmake/DependencyChecks.cmake)
include(cmake/SourceFiles.cmake)

# ============================================================================
# Setup project
# ============================================================================
setup_compiler()
validate_dependencies()
configure_project()

# ============================================================================
# Configuration options
# ============================================================================
option(ENABLE_DEBUG_VALIDATION "Enable debug validation" OFF)

# ============================================================================
# Link directories
# ============================================================================
link_directories("/usr/local/lib")

# ============================================================================
# Source files
# ============================================================================
get_all_sources()
add_executable(net_threat_detect ${ALL_SOURCES})

# ============================================================================
# Link libraries
# ============================================================================
target_link_libraries(net_threat_detect
        pthread
        pcap
        pcre
        yaml
        jansson)
