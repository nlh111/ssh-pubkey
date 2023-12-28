cmake_minimum_required(VERSION 3.0)
project("modifyKey")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g3 -O0 -fsanitize=address -static-libasan")
set(libs
    crypto
    ssl
)


add_executable(test errkey.cpp)
target_link_libraries(test PRIVATE ${libs})

