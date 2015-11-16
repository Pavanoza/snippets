cmake_minimum_required (VERSION 2.8)
project (DropAndRun)

set (srcs
    main.cpp
)

set (hdrs
    resource.h
)

set (rsrc
    resource.rc
)

add_executable (DropAndRun ${rsrc} ${hdrs} ${srcs})