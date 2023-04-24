cmake_minimum_required(VERSION 3.5)

# set(CMAKE_C_COMPILER_FORCED TRUE)
# set(CMAKE_CXX_COMPILER_FORCED TRUE)
set(CMAKE_SYSTEM_NAME Generic)

project(mod_code.elf C)



# Add C++11 support
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)


# Add the include directories for the header files
include_directories(include)

# Add the source files
set(SOURCES
    src/mod_code.c
)


# Define the executable and its sources
add_executable(mod_code.elf ${SOURCES})

string(FIND ${CMAKE_C_COMPILER} "tricore" tricore_found)
string(FIND ${CMAKE_C_COMPILER} "powerpc" powerpc_found)


if(tricore_found GREATER 0)
    # Link the necessary libraries
    target_link_libraries(mod_code.elf m -nocrt0 -nostartfiles -T${CMAKE_SOURCE_DIR}/tricore/tc21x_memory.ld -T${CMAKE_SOURCE_DIR}/tricore/tc21x_bsp_example.ld)
    message("tricore_found setting up with default linker")
elseif(powerpc_found GREATER 0)
    # Link the necessary libraries
    target_link_libraries(mod_code.elf m )
    message("powerpc_found setting up with default linker")

else()
    # Link the necessary libraries
    target_link_libraries(mod_code.elf m )


endif()

# Add the include directories
target_include_directories(mod_code.elf PRIVATE "${PROJECT_SOURCE_DIR}/include")




