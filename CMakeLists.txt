cmake_minimum_required(VERSION 3.22)
project(copypath)

set(CMAKE_CXX_STANDARD 20)

set(APP_ICON_RESOURCE_WINDOWS "${CMAKE_SOURCE_DIR}/resources/appicon.rc")

add_executable(copypath WIN32 ${APP_ICON_RESOURCE_WINDOWS} src/main.cpp)
