cmake_minimum_required(VERSION 3.10)
project(arpparse)

set(CMAKE_CXX_STANDARD 11)

include(FindPCAP.cmake)

add_executable(arpparse main.c)

target_link_libraries(arpparse ${PCAP_LIBRARY})