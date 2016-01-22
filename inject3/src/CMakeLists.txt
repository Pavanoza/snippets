cmake_minimum_required (VERSION 2.8)
project (Inject3)

add_definitions(-DUNICODE -D_UNICODE)

set (srcs
    main.cpp
)

set (hdrs
    main.h
    payload.h
)

add_executable (Inject3 ${hdrs} ${srcs})
