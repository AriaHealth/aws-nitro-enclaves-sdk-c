include(CMakeFindDependencyMacro)

find_dependency(aws-c-io)
find_dependency(aws-c-http)
find_dependency(aws-c-auth)

if (BUILD_SHARED_LIBS)
    include(${CMAKE_CURRENT_LIST_DIR}/shared/@PROJECT_NAME@-targets.cmake)
else()
    include(${CMAKE_CURRENT_LIST_DIR}/static/@PROJECT_NAME@-targets.cmake)
endif()

