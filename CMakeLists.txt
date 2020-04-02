cmake_minimum_required(VERSION 3.5)

project(sipmitm LANGUAGES C)

add_executable(sipmitm main.c)
target_link_libraries(sipmitm osipparser2 netfilter_queue)

INSTALL(TARGETS sipmitm RUNTIME DESTINATION /usr/bin/)
