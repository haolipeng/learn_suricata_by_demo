# CompilerOptions.cmake - Compiler flags and options module
# This module handles all compiler-specific settings

# ============================================================================
# Compiler flags for different build types
# ============================================================================
function(setup_compiler_flags)
    # Set C standard
    set(CMAKE_C_STANDARD 99 PARENT_SCOPE)
    set(CMAKE_C_STANDARD_REQUIRED ON PARENT_SCOPE)
    set(CMAKE_C_EXTENSIONS OFF PARENT_SCOPE)
    
    # Debug build flags
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -Wall -Werror -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing" PARENT_SCOPE)
    
    # Release build flags
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_Release} -O2 -DNDEBUG -Wall -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing" PARENT_SCOPE)
    
    # RelWithDebInfo build flags
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -O2 -g -Wall -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing" PARENT_SCOPE)
    
    # MinSizeRel build flags
    set(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} -Os -DNDEBUG -Wall -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing" PARENT_SCOPE)
    
    message(STATUS "Compiler flags configured")
endfunction()

# ============================================================================
# Build type configuration
# ============================================================================
function(setup_build_type)
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE "debug" PARENT_SCOPE)
        message(STATUS "Build type not specified, defaulting to debug")
    endif()
    
    message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
endfunction()

# ============================================================================
# Main compiler setup function
# ============================================================================
function(setup_compiler)
    message(STATUS "Setting up compiler...")
    
    setup_build_type()
    setup_compiler_flags()
    
    message(STATUS "Compiler setup completed")
endfunction() 