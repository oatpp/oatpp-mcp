//
// Created by Leonid S on 12/9/24.
//

#include "ServerTest.hpp"

#include "api/controller/UserController.hpp"

#include "prompts/CodeReview.hpp"
#include "tools/Logger.hpp"
#include "resources/File.hpp"
#include "resources/ProjectFiles.hpp"

#include "oatpp-mcp/Server.hpp"
#include "oatpp-mcp/utils/JsonSchema.hpp"

#include "oatpp/web/server/HttpConnectionHandler.hpp"
#include "oatpp/network/tcp/server/ConnectionProvider.hpp"
#include "oatpp/network/Server.hpp"

#include <iostream>

namespace oatpp { namespace mcp { namespace app {

namespace {

void runHttpServer(oatpp::mcp::Server mcpServer) {

  auto router = oatpp::web::server::HttpRouter::createShared();
  router->addController(mcpServer.getSseController());


  auto json = std::make_shared<oatpp::json::ObjectMapper>();
  json->serializerConfig().json.useBeautifier = true;

  auto mappers = std::make_shared<oatpp::web::mime::ContentMappers>();
  mappers->putMapper(json);
  mappers->setDefaultMapper("application/json");

  auto userController = std::make_shared<UserController>(mappers);
  mcpServer.addEndpoints(userController->getEndpoints());


  auto connectionProvider = oatpp::network::tcp::server::ConnectionProvider::createShared
    ({"0.0.0.0", 3001, oatpp::network::Address::IP_4});

  auto connectionHandler =  oatpp::web::server::HttpConnectionHandler::createShared(router);
  oatpp::network::Server server(connectionProvider, connectionHandler);

  OATPP_LOGi("MyApp", "Server running on port {}", connectionProvider->getProperty("port").toString());
  server.run();

}

}

void ServerTest::onRun() {

  oatpp::mcp::Server::Config config;
  config.ssePrefix = "mcp/";

  /*
   * The names this server is willing to be addressed by. It binds 0.0.0.0 below, so leaving this
   * empty means any DNS name that ever resolves to this machine - including one somebody else is
   * pointing here - is accepted. See SECURITY-FINDINGS.md, finding F4.
   */
  config.access.allowedHosts = {"localhost", "127.0.0.1"};

  /* Create MCP server */
  oatpp::mcp::Server server(config);

  /* Add prompts */
  server.addPrompt(std::make_shared<prompts::CodeReview>());

  /* Add tools */
  //server.addTool(std::make_shared<tools::Logger>());

  /* Add resource */
  server.addResource(std::make_shared<resource::File>());

  /* Add resource template */
  server.addResource(std::make_shared<resource::ProjectFiles>());

//  auto json = std::make_shared<oatpp::json::ObjectMapper>();
//  json->serializerConfig().json.useBeautifier = true;
//
//  auto mappers = std::make_shared<oatpp::web::mime::ContentMappers>();
//  mappers->putMapper(json);
//  mappers->setDefaultMapper("application/json");
//
//  auto userController = std::make_shared<UserController>(mappers);
//  server.addEndpoints(userController->getEndpoints());


  //server.stdioListen();

  /* Run HTTP server */
  runHttpServer(server);

}

}}}
