//
// Entry point of the `mcp-server-demo` application.
//
// This is the binary that used to be called `module-tests`. It starts an MCP SSE server on port
// 3001 and serves the demo UserController as MCP tools; it runs until interrupted and is meant to
// be driven by hand (see README.md). It is not registered with CTest - automated tests live in
// oatpp-mcp/tests/ and are run by `module-tests`.
//

#include "ServerTest.hpp"

#include "oatpp/Environment.hpp"

#include <iostream>

int main() {

  oatpp::Environment::init();

  OATPP_RUN_TEST(oatpp::mcp::app::ServerTest);

  oatpp::Environment::destroy();

  return EXIT_SUCCESS;
}
