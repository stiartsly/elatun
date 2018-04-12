cmake_minimum_required(VERSION 3.10)
#set(CMAKE_VERBOSE_MAKEFILE on)

project(secure_tunnel C)

option(SECURE_TUNNEL_INSTALL "enable to install program" OFF)

set(dist_targets secure_tunnel)
add_subdirectory(src)
