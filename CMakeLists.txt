cmake_minimum_required(VERSION 3.10)
project(snitch)

add_subdirectory(sloop)

add_executable(snitch main.c)
target_link_libraries(snitch sloop)

