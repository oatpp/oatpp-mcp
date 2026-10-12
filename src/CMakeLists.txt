
add_library(${OATPP_THIS_MODULE_NAME}
        oatpp-mcp/capabilities/Prompt.cpp
        oatpp-mcp/capabilities/Prompt.hpp
        oatpp-mcp/capabilities/Resource.hpp
        oatpp-mcp/capabilities/Resource.cpp
        oatpp-mcp/capabilities/Tool.cpp
        oatpp-mcp/capabilities/Tool.hpp
        oatpp-mcp/capabilities/Utils.cpp
        oatpp-mcp/capabilities/Utils.hpp
        oatpp-mcp/dto/Capabilities.hpp
        oatpp-mcp/dto/ClientInfo.hpp
        oatpp-mcp/dto/JsonRpc.hpp
        oatpp-mcp/dto/Methods.hpp
        oatpp-mcp/dto/ServerInfo.hpp
        oatpp-mcp/event/EventStream.cpp
        oatpp-mcp/event/EventStream.hpp
        oatpp-mcp/event/Server.cpp
        oatpp-mcp/event/Server.hpp
        oatpp-mcp/event/Session.cpp
        oatpp-mcp/event/Session.hpp
        oatpp-mcp/sse/Controller.cpp
        oatpp-mcp/sse/Controller.hpp
        oatpp-mcp/sse/ReadCallback.cpp
        oatpp-mcp/sse/ReadCallback.hpp
        oatpp-mcp/utils/AccessGuard.cpp
        oatpp-mcp/utils/AccessGuard.hpp
        oatpp-mcp/utils/ApiBridge.cpp
        oatpp-mcp/utils/ApiBridge.hpp
        oatpp-mcp/utils/HttpSanitize.cpp
        oatpp-mcp/utils/HttpSanitize.hpp
        oatpp-mcp/utils/LogSafe.cpp
        oatpp-mcp/utils/LogSafe.hpp
        oatpp-mcp/utils/Uuid.cpp
        oatpp-mcp/utils/Uuid.hpp
        oatpp-mcp/utils/JsonSchema.cpp
        oatpp-mcp/utils/JsonSchema.hpp
        oatpp-mcp/Listener.cpp
        oatpp-mcp/Listener.hpp
        oatpp-mcp/Server.cpp
        oatpp-mcp/Server.hpp
)

set_target_properties(${OATPP_THIS_MODULE_NAME} PROPERTIES
        CXX_STANDARD 17
        CXX_EXTENSIONS OFF
        CXX_STANDARD_REQUIRED ON
)

if(OATPP_MODULES_LOCATION STREQUAL OATPP_MODULES_LOCATION_EXTERNAL)
    add_dependencies(${OATPP_THIS_MODULE_NAME} ${LIB_OATPP_EXTERNAL})
endif()

target_link_oatpp(${OATPP_THIS_MODULE_NAME})

target_include_directories(${OATPP_THIS_MODULE_NAME}
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

## TODO link dependencies here (if some)

#######################################################################################################
## install targets

if(OATPP_INSTALL)
    include("../cmake/module-install.cmake")
endif()
