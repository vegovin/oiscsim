
project(oiscsim)

cmake_minimum_required(VERSION 2.8.8)

list(APPEND CMAKE_C_FLAGS "-g -Wall -Werror -O2")

add_executable(oiscsim
  oiscsim.c)