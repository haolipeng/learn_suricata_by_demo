# DependencyChecks.cmake - Dependency validation module
# This module checks for required dependencies and provides helpful error messages

# ============================================================================
# Required dependencies
# ============================================================================
set(REQUIRED_LIBRARIES
    "pthread"
    "pcap"
    "pcre"
    "yaml"
    "jansson"
)

set(REQUIRED_HEADERS
    "linux/if_packet.h"
    "linux/if_ether.h"
    "pcap/pcap.h"
    "pcre.h"
    "yaml.h"
    "jansson.h"
)

# ============================================================================
# Check required headers
# ============================================================================
function(check_required_headers)
    message(STATUS "Checking required headers...")
    
    foreach(header ${REQUIRED_HEADERS})
        string(REPLACE "/" "_" header_var "${header}")
        string(REPLACE "." "_" header_var "${header_var}")
        string(TOUPPER "${header_var}" header_var)
        
        check_include_file("${header}" HAVE_${header_var})
        
        if(NOT HAVE_${header_var})
            message(FATAL_ERROR "Required header '${header}' not found. Please install the corresponding development package.")
        endif()
    endforeach()
    
    message(STATUS "All required headers found")
endfunction()

# ============================================================================
# Check required libraries
# ============================================================================
function(check_required_libraries)
    message(STATUS "Checking required libraries...")
    
    foreach(lib ${REQUIRED_LIBRARIES})
        string(TOUPPER "${lib}" lib_var)
        
        if(lib STREQUAL "pthread")
            check_library_exists("${lib}" "pthread_create" "" HAVE_LIB${lib_var})
        elseif(lib STREQUAL "pcap")
            check_library_exists("${lib}" "pcap_open_live" "" HAVE_LIB${lib_var})
        elseif(lib STREQUAL "pcre")
            check_library_exists("${lib}" "pcre_compile" "" HAVE_LIB${lib_var})
        elseif(lib STREQUAL "yaml")
            check_library_exists("${lib}" "yaml_parser_initialize" "" HAVE_LIB${lib_var})
        elseif(lib STREQUAL "jansson")
            check_library_exists("${lib}" "json_loads" "" HAVE_LIB${lib_var})
        endif()
        
        if(NOT HAVE_LIB${lib_var})
            message(FATAL_ERROR "Required library '${lib}' not found. Please install the corresponding development package.")
        endif()
    endforeach()
    
    message(STATUS "All required libraries found")
endfunction()

# ============================================================================
# Check system requirements
# ============================================================================
function(check_system_requirements)
    message(STATUS "Checking system requirements...")
    
    # Check CMake version
    if(CMAKE_VERSION VERSION_LESS 3.16)
        message(FATAL_ERROR "CMake 3.16 or higher is required. Current version: ${CMAKE_VERSION}")
    endif()
    
    # Check C compiler
    if(NOT CMAKE_C_COMPILER)
        message(FATAL_ERROR "C compiler not found")
    endif()
    
    # Check if we're on Linux (for AF_PACKET support)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(WARNING "This project is designed for Linux systems. Some features may not work on ${CMAKE_SYSTEM_NAME}")
    endif()
    
    message(STATUS "System requirements met")
endfunction()

# ============================================================================
# Main dependency check function
# ============================================================================
function(validate_dependencies)
    message(STATUS "Validating dependencies...")
    
    check_system_requirements()
    check_required_headers()
    check_required_libraries()
    
    message(STATUS "All dependencies validated successfully")
endfunction() 