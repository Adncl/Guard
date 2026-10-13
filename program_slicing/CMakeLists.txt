cmake_minimum_required(VERSION 3.16)
project(LLVMPassProject)

# Set LLVM path
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
find_package(Clang REQUIRED CONFIG)
find_package(nlohmann_json REQUIRED)

# Add LLVM module path
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

# Set compile options
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-rtti -g -O0")

# Add definitions
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# Include LLVM and local header directories
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS}) # Use SYSTEM keyword to avoid some compiler warnings
include_directories(${PROJECT_SOURCE_DIR}/include)

# Add subdirectory
add_subdirectory(src)
