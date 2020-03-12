cmake_minimum_required(VERSION 3.8)
project(server)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE release)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

find_package(yaml-cpp REQUIRED)
find_package(Boost REQUIRED system)

add_executable(server main.cpp utils.cpp)

target_include_directories(server PUBLIC ${YAML_CPP_INCLUDE_DIR})
target_link_libraries(server ${YAML_CPP_LIBRARIES} Boost::boost Boost::system)
