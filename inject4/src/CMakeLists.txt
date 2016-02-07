cmake_minimum_required (VERSION 2.8)
project (Inject4)

add_definitions(-DUNICODE -D_UNICODE)

set (srcs
    main.cpp
)

set (hdrs
    main.h
)

add_executable (Inject4 ${hdrs} ${srcs})
