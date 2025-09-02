# SourceFiles.cmake - Automatic source file discovery module
# This module automatically scans src/ subdirectories for .h and .c files

# ============================================================================
# Function to automatically discover source files in a directory
# ============================================================================
function(discover_source_files DIR_PATH)
    # Get all .c and .h files in the directory
    file(GLOB_RECURSE C_FILES "${DIR_PATH}/*.c")
    file(GLOB_RECURSE H_FILES "${DIR_PATH}/*.h")
    
    # Set variables in parent scope
    set(SOURCES_${DIR_PATH} ${C_FILES} ${H_FILES} PARENT_SCOPE)
endfunction()

# ============================================================================
# Function to get all source files from src/ directory
# ============================================================================
function(get_all_sources)
    # Discover all source files in src/ directory
    discover_source_files("${CMAKE_SOURCE_DIR}/src")
    
    # Get main source files
    set(MAIN_SOURCES
        main.c
        src/base.h
    )
    
    # Combine all sources
    set(ALL_SOURCES
        ${MAIN_SOURCES}
        ${SOURCES_${CMAKE_SOURCE_DIR}/src}
    PARENT_SCOPE)
    
    # Print summary
    message(STATUS "Total source files: ${ALL_SOURCES}")
endfunction()

# ============================================================================
# Alternative: Get sources by subdirectory (if you want more control)
# ============================================================================
function(get_sources_by_subdir)
    # Get list of subdirectories in src/
    file(GLOB SRC_SUBDIRS LIST_DIRECTORIES true "${CMAKE_SOURCE_DIR}/src/*")
    
    foreach(SUBDIR ${SRC_SUBDIRS})
        if(IS_DIRECTORY ${SUBDIR})
            # Get directory name
            get_filename_component(DIR_NAME ${SUBDIR} NAME)
            
            # Discover files in this subdirectory
            file(GLOB_RECURSE SUBDIR_C_FILES "${SUBDIR}/*.c")
            file(GLOB_RECURSE SUBDIR_H_FILES "${SUBDIR}/*.h")
            
            # Set variable for this subdirectory
            set(SOURCES_${DIR_NAME} ${SUBDIR_C_FILES} ${SUBDIR_H_FILES} PARENT_SCOPE)
            
            message(STATUS "Subdirectory ${DIR_NAME}: ${SOURCES_${DIR_NAME}}")
        endif()
    endforeach()
endfunction()