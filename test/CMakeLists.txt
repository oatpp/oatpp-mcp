#-----------------------------------------------------------------------------------------------------------------------
# Shared helpers
#-----------------------------------------------------------------------------------------------------------------------

function(mcp_configure_target TARGET_NAME)
    set_target_properties(${TARGET_NAME} PROPERTIES
            CXX_STANDARD 17
            CXX_EXTENSIONS OFF
            CXX_STANDARD_REQUIRED ON
    )

    target_include_directories(${TARGET_NAME}
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    )

    if(OATPP_MODULES_LOCATION STREQUAL OATPP_MODULES_LOCATION_EXTERNAL)
        add_dependencies(${TARGET_NAME} ${LIB_OATPP_EXTERNAL})
    endif()

    add_dependencies(${TARGET_NAME} ${OATPP_THIS_MODULE_NAME})

    target_link_oatpp(${TARGET_NAME})

    target_link_libraries(${TARGET_NAME}
            PRIVATE ${OATPP_THIS_MODULE_NAME}
    )

    ## TODO link dependencies here (if some)
endfunction()

#-----------------------------------------------------------------------------------------------------------------------
# Demo application
#
# `app/ServerTest` starts an MCP server on port 3001 and runs until interrupted - it is a manual
# playground, not an automated test. It is deliberately NOT registered with CTest: a test binary
# that never returns gives no signal at all.
#-----------------------------------------------------------------------------------------------------------------------

set(MCP_DEMO_SOURCES
        oatpp-mcp/app/api/controller/UserController.hpp
        oatpp-mcp/app/api/dto/PageDto.hpp
        oatpp-mcp/app/api/dto/StatusDto.hpp
        oatpp-mcp/app/api/dto/UserDto.hpp
        oatpp-mcp/app/prompts/CodeReview.cpp
        oatpp-mcp/app/prompts/CodeReview.hpp
        oatpp-mcp/app/resources/File.hpp
        oatpp-mcp/app/resources/File.cpp
        oatpp-mcp/app/resources/ProjectFiles.cpp
        oatpp-mcp/app/resources/ProjectFiles.hpp
        oatpp-mcp/app/tools/Logger.cpp
        oatpp-mcp/app/tools/Logger.hpp
        oatpp-mcp/app/ServerTest.cpp
        oatpp-mcp/app/ServerTest.hpp
        oatpp-mcp/app/main.cpp
)

add_executable(mcp-server-demo ${MCP_DEMO_SOURCES})
mcp_configure_target(mcp-server-demo)

#-----------------------------------------------------------------------------------------------------------------------
# Tests
#
# Every test is a class in oatpp-mcp/tests/ and is listed exactly once, in MCP_TESTS. Both the
# compiled sources and the CTest entries are derived from that list, so a test cannot be registered
# with CTest while being left out of the compile (or the other way round).
#
# Each test also runs in its own process (`--test=<name>`), which keeps tests that own threads,
# sockets or the shared `mcp.bridge.virtualhost` interface from interfering with each other.
#-----------------------------------------------------------------------------------------------------------------------

set(MCP_TESTS
        SessionIdTest
        ListenerMessageTest
        ToolHttpFramingTest
)

set(MCP_TEST_SOURCES
        oatpp-mcp/tests.cpp
        oatpp-mcp/tests/TestChecks.hpp
)

foreach(MCP_TEST ${MCP_TESTS})
    list(APPEND MCP_TEST_SOURCES
            oatpp-mcp/tests/${MCP_TEST}.hpp
            oatpp-mcp/tests/${MCP_TEST}.cpp
    )
endforeach()

add_executable(module-tests ${MCP_TEST_SOURCES})
mcp_configure_target(module-tests)

foreach(MCP_TEST ${MCP_TESTS})
    add_test(NAME ${MCP_TEST} COMMAND module-tests --test=${MCP_TEST})
    set_tests_properties(${MCP_TEST} PROPERTIES TIMEOUT 60)
endforeach()

# `module-tests` with no arguments runs the whole suite in one process. Registered as well so that a
# single-process run - which is what `OATPP_RUN_TEST` gave before - is still covered by `ctest`.
add_test(NAME AllTests COMMAND module-tests)
set_tests_properties(AllTests PROPERTIES TIMEOUT 120)
