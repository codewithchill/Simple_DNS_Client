cmake_minimum_required(VERSION 3.10)

# Project Name
project("DNS Client" C)

# Set C Flags
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -Wextra")

# Include directories (header files)
include_directories(include)

# Automatically find all .c files in src and subdirectories
file(GLOB_RECURSE SOURCES "src/*.c")

# Create the executable in the 'build' folder
add_executable(app ${SOURCES})
