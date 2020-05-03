cmake_minimum_required(VERSION 3.8)
project(server)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE release)
set(CMAKE_CXX_FLAGS -pthread)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

option(NoEncrypt "NoEncrypt" OFF)

find_package(yaml-cpp REQUIRED)
find_package(Boost REQUIRED system)

if(NOT NoEncrypt)
    find_package(PkgConfig)

    if(PKG_CONFIG_FOUND)
        message("Found pkgconfig, will use it to config libsodium")
        pkg_check_modules(SODIUM REQUIRED libsodium)
        if(SODIUM_FOUND)
            message("Found libsodium, enabling encryption")
            add_definitions(-DSUPPORT_ENCRYPTION)
        endif()
    else()
        message("Pkgconfig not found, libsodium not available")
    endif()
else()
    message("Compile without encryption support")
endif()

add_executable(server main.cpp utils.cpp)

target_include_directories(server PUBLIC ${YAML_CPP_INCLUDE_DIR} ${SODIUM_INCLUDE_DIRS})
target_link_libraries(server ${YAML_CPP_LIBRARIES} Boost::boost Boost::system ${SODIUM_LDFLAGS})
