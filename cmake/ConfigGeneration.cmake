# ConfigGeneration.cmake - Configuration generation module
# This module handles autoconf.h generation and project configuration

# ============================================================================
# Project configuration
# ============================================================================
function(setup_project_config)
    # Package information
    set(PACKAGE "suricata" PARENT_SCOPE)
    set(PACKAGE_NAME "Suricata" PARENT_SCOPE)
    set(PACKAGE_VERSION "7.0.0-dev" PARENT_SCOPE)
    set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}" PARENT_SCOPE)
    set(PACKAGE_TARNAME "suricata" PARENT_SCOPE)
    set(PACKAGE_BUGREPORT "bug-reports@suricata.io" PARENT_SCOPE)
    set(PACKAGE_URL "https://suricata.io/" PARENT_SCOPE)

    # Version components
    set(VERSION "${PACKAGE_VERSION}" PARENT_SCOPE)
    set(VERSION_MAJOR 7 PARENT_SCOPE)
    set(VERSION_MINOR 0 PARENT_SCOPE)
    set(VERSION_PATCH 0 PARENT_SCOPE)

    # Set cache line size (typically 64 bytes on x86_64)
    set(CLS 64 PARENT_SCOPE)

    # Set directories
    set(CONFIG_DIR "/etc/suricata/" PARENT_SCOPE)
    set(DATA_DIR "/var/lib/suricata/data" PARENT_SCOPE)
    
    # Make these variables available globally for autoconf.h generation
    set(PACKAGE "net_threat_detect" CACHE STRING "Package name")
    set(PACKAGE_NAME "net_threat_detect" CACHE STRING "Package display name")
    set(PACKAGE_VERSION "0.0.1" CACHE STRING "Package version")
    set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}" CACHE STRING "Package string")
    set(PACKAGE_TARNAME "net_threat_detect" CACHE STRING "Package tarball name")
    set(VERSION "${PACKAGE_VERSION}" CACHE STRING "Version")
    set(VERSION_MAJOR 0 CACHE STRING "Major version")
    set(VERSION_MINOR 0 CACHE STRING "Minor version")
    set(VERSION_PATCH 1 CACHE STRING "Patch version")
    set(CONFIG_DIR "/etc/suricata/" CACHE STRING "Configuration directory")
    set(DATA_DIR "/var/lib/suricata/data" CACHE STRING "Data directory")
endfunction()

# ============================================================================
# Build configuration
# ============================================================================
function(setup_build_config)
    # Set DEBUG based on build type
    if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "debug")
        set(DEBUG 1 PARENT_SCOPE)
    endif()
    
    # Set debug validation if enabled
    if(ENABLE_DEBUG_VALIDATION)
        set(DEBUG_VALIDATION 1 PARENT_SCOPE)
    endif()
endfunction()

# ============================================================================
# Generate autoconf.h
# ============================================================================
function(generate_autoconf_h)
    # Generate autoconf.h from template in source directory
    configure_file(
        ${CMAKE_SOURCE_DIR}/src/common/autoconf.h.in
        ${CMAKE_SOURCE_DIR}/src/common/autoconf.h
        @ONLY
    )
    
    message(STATUS "Generated autoconf.h: ${CMAKE_SOURCE_DIR}/src/common/autoconf.h")
endfunction()

# ============================================================================
# Setup include directories
# ============================================================================
function(setup_include_directories)
    # Include directories
    include_directories(${CMAKE_SOURCE_DIR}/src)
    include_directories(${CMAKE_SOURCE_DIR}/third-party/include)
    include_directories("/usr/local/include")
    
    message(STATUS "Include directories configured")
endfunction()

# ============================================================================
# Main configuration function
# ============================================================================
function(configure_project)
    message(STATUS "Configuring project...")
    
    # Setup all configurations
    setup_project_config()
    setup_build_config()
    generate_autoconf_h()
    setup_include_directories()
    
    message(STATUS "Project configuration completed")
endfunction() 