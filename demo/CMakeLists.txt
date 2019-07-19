cmake_minimum_required(VERSION 2.8)
include ("env-qca4531.txt")

project (demo)

if(${OS_NAME} STREQUAL "linux")
add_definitions(-std=gnu99 -D__USE_GNU -D_GNU_SOURCE)
else()
message("====>>>>>OS_NAME: " ${OS_NAME})
endif()


set(target demo)
set(src_list main.c)
set(lib_list pthread)

add_executable(${target} ${src_list})
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

target_link_libraries(${target} ${lib_list})


