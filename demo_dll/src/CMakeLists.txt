cmake_minimum_required (VERSION 2.8)
project (TestLib)

set (srcs
    main.cpp
)

set (hdrs
    main.h
)

add_library (TestLib SHARED ${hdrs} ${srcs} main.def)