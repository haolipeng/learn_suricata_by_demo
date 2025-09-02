# SystemChecks.cmake - System feature detection module
# This module handles all system capability checks and feature detection

# Include required CMake modules
include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckStructHasMember)

# ============================================================================
# Linux-specific feature detection
# ============================================================================
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Check for TPACKET_V3 support (Linux kernel 2.6.27+)
    check_struct_has_member("struct tpacket3_hdr" tp_next_offset "linux/if_packet.h" HAVE_TPACKET_V3)
    
    # Alternative check: try to compile a simple test program
    if(NOT HAVE_TPACKET_V3)
        include(CheckCCompilerFlag)
        set(CMAKE_REQUIRED_INCLUDES "linux/if_packet.h")
        check_c_source_compiles("
            #include <linux/if_packet.h>
            int main() {
                struct tpacket3_hdr hdr;
                (void)hdr.tp_next_offset;
                return 0;
            }
        " HAVE_TPACKET_V3_COMPILE)
        
        if(HAVE_TPACKET_V3_COMPILE)
            set(HAVE_TPACKET_V3 1)
        endif()
    endif()
    
    # Set AF_PACKET support
    set(HAVE_AF_PACKET 1)
    
    message(STATUS "TPACKET_V3 support: ${HAVE_TPACKET_V3}")
endif()

# ============================================================================
# Header file availability checks
# ============================================================================
check_include_file("arpa/inet.h" HAVE_ARPA_INET_H)
check_include_file("assert.h" HAVE_ASSERT_H)
check_include_file("ctype.h" HAVE_CTYPE_H)
check_include_file("dirent.h" HAVE_DIRENT_H)
check_include_file("dlfcn.h" HAVE_DLFCN_H)
check_include_file("errno.h" HAVE_ERRNO_H)
check_include_file("fcntl.h" HAVE_FCNTL_H)
check_include_file("inttypes.h" HAVE_INTTYPES_H)
check_include_file("limits.h" HAVE_LIMITS_H)
check_include_file("netdb.h" HAVE_NETDB_H)
check_include_file("netinet/in.h" HAVE_NETINET_IN_H)
check_include_file("stdint.h" HAVE_STDINT_H)
check_include_file("stdio.h" HAVE_STDIO_H)
check_include_file("stdlib.h" HAVE_STDLIB_H)
check_include_file("string.h" HAVE_STRING_H)
check_include_file("strings.h" HAVE_STRINGS_H)
check_include_file("sys/socket.h" HAVE_SYS_SOCKET_H)
check_include_file("sys/stat.h" HAVE_SYS_STAT_H)
check_include_file("sys/time.h" HAVE_SYS_TIME_H)
check_include_file("sys/types.h" HAVE_SYS_TYPES_H)
check_include_file("time.h" HAVE_TIME_H)
check_include_file("unistd.h" HAVE_UNISTD_H)

# ============================================================================
# Function availability checks
# ============================================================================
check_function_exists("alarm" HAVE_ALARM)
check_function_exists("atexit" HAVE_ATEXIT)
check_function_exists("bzero" HAVE_BZERO)
check_function_exists("gettimeofday" HAVE_GETTIMEOFDAY)
check_function_exists("memset" HAVE_MEMSET)
check_function_exists("strchr" HAVE_STRCHR)
check_function_exists("strerror" HAVE_STRERROR)
check_function_exists("strlcat" HAVE_STRLCAT)
check_function_exists("strlcpy" HAVE_STRLCPY)
check_function_exists("strstr" HAVE_STRSTR)

# ============================================================================
# Library availability checks
# ============================================================================
check_library_exists("pcap" "pcap_open_live" "" HAVE_LIBPCAP)
check_library_exists("pcre" "pcre_compile" "" HAVE_LIBPCRE)
check_library_exists("pthread" "pthread_create" "" HAVE_LIBPTHREAD)
check_library_exists("yaml" "yaml_parser_initialize" "" HAVE_LIBYAML)

# ============================================================================
# Print detection results
# ============================================================================
message(STATUS "System feature detection completed:")
message(STATUS "  - TPACKET_V3: ${HAVE_TPACKET_V3}")
message(STATUS "  - AF_PACKET: ${HAVE_AF_PACKET}")
message(STATUS "  - libpcap: ${HAVE_LIBPCAP}")
message(STATUS "  - libpcre: ${HAVE_LIBPCRE}")
message(STATUS "  - libpthread: ${HAVE_LIBPTHREAD}")
message(STATUS "  - libyaml: ${HAVE_LIBYAML}") 