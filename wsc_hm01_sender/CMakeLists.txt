cmake_minimum_required(VERSION 3.19)
project(wsc_hm01_sender)

set(CMAKE_CXX_STANDARD 11)

include_directories(E:\\MinGW\\include)
link_directories(E:\\MinGW\\lib)
link_libraries(ws2_32)

add_executable(wsc_hm01_sender main.cpp data.hpp DES.hpp)