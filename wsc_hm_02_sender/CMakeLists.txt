cmake_minimum_required(VERSION 3.19)
project(wsc_hm_02_sender)

set(CMAKE_CXX_STANDARD 11)

include_directories(E:\\MinGW\\include)
link_directories(E:\\MinGW\\lib)
link_libraries(ws2_32)

add_executable(wsc_hm_02_sender src/main.cpp include/RSA.h include/pch.h include/data.hpp include/DES.hpp)