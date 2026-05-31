cmake_minimum_required(VERSION 3.10)
project(threat-intel C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)

add_executable(threat-intel main.c api.c db.c)

target_include_directories(threat-intel PRIVATE ${GTK3_INCLUDE_DIRS})

target_link_libraries(threat-intel
    ${GTK3_LIBRARIES}
    curl
    cjson
    sqlite3
)