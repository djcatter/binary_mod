cmake_minimum_required(VERSION 3.5)

# set(CMAKE_C_COMPILER_FORCED TRUE)
# set(CMAKE_CXX_COMPILER_FORCED TRUE)
set(CMAKE_SYSTEM_NAME Generic)

project(simple_ecu.elf C)

if(NOT "${BUILD_VERSION}")
  set(BUILD_VERSION SimpleEcu_1.3)
endif()

configure_file( src/version_config.h.in ${CMAKE_BINARY_DIR}/generated/version_config.h )
include_directories( ${CMAKE_BINARY_DIR}/generated/ )

# Add C++11 support
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)


# Add the include directories for the header files
include_directories(include)



# Add the source files
set(SOURCES
    characteristicshandler/get_curve_value.c
    characteristicshandler/get_map_value.c
    src/fuelandspark.c
    src/main.c
)


# Define the executable and its sources
add_executable(simple_ecu.elf ${SOURCES})


string(FIND ${CMAKE_C_COMPILER} "tricore" tricore_found)
string(FIND ${CMAKE_C_COMPILER} "powerpc" powerpc_found)
string(FIND ${CMAKE_C_COMPILER} "gcc" gcc_found)

if(tricore_found GREATER 0)
    # Link the necessary libraries
    if(BUILD_VERSION EQUAL SimpleEcu_1.2)
        set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -meabi")
    else()
        set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -meabi -O3")
    endif()
    target_link_libraries(simple_ecu.elf m -nocrt0 -nostartfiles -T${CMAKE_SOURCE_DIR}/tricore/tc21x_memory.ld -T${CMAKE_SOURCE_DIR}/tricore/tc21x_simple_ecu.ld )
    message("tricore_found setting up with default linker")
    
elseif(powerpc_found GREATER 0)
    # Link the necessary libraries
    set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -meabi")
    target_link_libraries(simple_ecu.elf m )
    message("powerpc_found setting up with default linker")

else()
    # Link the necessary libraries
    set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -meabi")
    target_link_libraries(simple_ecu.elf m )


endif()

# Add the include directories
target_include_directories(simple_ecu.elf PRIVATE "${PROJECT_SOURCE_DIR}/include")

# Add the test files
set(TEST_SOURCES
    test/get_curve_value_test_cpputest.cpp
)

# # Add CPPUTest
# add_subdirectory(CPPUTest)
# include_directories(${CPPUTEST_INCLUDE_DIRS})

# # Create the executable
# add_executable(my_project ${SOURCES} ${TEST_SOURCES})

# # Link the libraries
# target_link_libraries(my_project ${CPPUTEST_LIBRARIES})


# # Unity configuration
# set(UNITY_TEST_SOURCES test/get_curve_value_test_unity.c)
# set(UNITY_HOME /path/to/unity)

# include_directories(${UNITY_HOME}/src)
# include_directories(src)
# add_executable(get_curve_value_test_unity ${UNITY_TEST_SOURCES} characteristicshandler/get_curve_value.c)