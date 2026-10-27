//
// Created by Leonid S on 12/9/24.
//

#include "Tool.hpp"

#include "oatpp-mcp/capabilities/Utils.hpp"
#include "oatpp-mcp/utils/HttpSanitize.hpp"

#include "oatpp/web/protocol/http/outgoing/BufferBody.hpp"
#include "oatpp/base/Log.hpp"

namespace oatpp { namespace mcp { namespace capabilities {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// EndpointTool

EndpointTool::EndpointTool(const std::shared_ptr<web::server::api::Endpoint>& endpoint,
                           const Components& components)
  : m_endpoint(endpoint)
  , m_components(components)
{}

oatpp::Tree EndpointTool::generateEndpointSchema() const {

  oatpp::data::mapping::Tree schema;
  oatpp::data::mapping::Tree defs;

  schema["type"] = "object";

  auto& params = schema["properties"];
  params.setMap({});

  auto& required = schema["required"];
  required.setVector(0);

  auto& info = *m_endpoint->info();

  for(auto& pp : info.pathParams.getOrder()) {
    auto& param = info.pathParams[pp];
    data::mapping::Tree req;
    req = param.name;
    required.getVector().push_back(req);
    params[param.name] = m_components.schemaMapper->map(param.type, defs);
  }

  for(auto& hp : info.headers.getOrder()) {
    auto& param = info.headers[hp];
    data::mapping::Tree req;
    req = param.name;
    required.getVector().push_back(req);
    params[param.name] = m_components.schemaMapper->map(param.type, defs);
  }

  for(auto& qp : info.queryParams.getOrder()) {
    auto& param = info.queryParams[qp];
    if(param.required) {
      data::mapping::Tree req;
      req = param.name;
      required.getVector().push_back(req);
    }
    params[param.name] = m_components.schemaMapper->map(param.type, defs);
  }

  if(info.body.name != nullptr && info.body.type != nullptr) {
    auto& param = info.body;
    if(param.required) {
      data::mapping::Tree req;
      req = param.name;
      required.getVector().push_back(req);
    }
    params[param.name] = m_components.schemaMapper->map(param.type, defs);
  }

  if(!defs.isUndefined()) {
    schema["$defs"] = std::move(defs);
  }

  return schema;

}

oatpp::String EndpointTool::prepareEndpointPath(const std::unordered_map<oatpp::String, oatpp::String>& args, Error& error) const {

  auto& info = *m_endpoint->info();
  oatpp::String pathTail;
  {
    oatpp::data::stream::BufferOutputStream ss(256);
    for(auto& qp : info.queryParams.getOrder()) {
      auto& param = info.queryParams[qp];
      auto it = args.find(param.name);
      if(it != args.end()) {
        if (ss.getCurrentPosition() == 0) {
          ss << "?";
        } else {
          ss << "&";
        }
        /*
         * Both halves are encoded: a parameter name is an argument name, and an argument name is
         * chosen by whoever described the tool - which for an endpoint exposed as a tool is not
         * necessarily somebody who reviewed this request.
         */
        ss << utils::HttpSanitize::encodeQueryComponent(param.name)
           << "="
           << utils::HttpSanitize::encodeQueryComponent(it->second);
      }
    }
    pathTail = ss.toString();
  }

  /*
   * Pattern::reconstruct() substitutes path variables verbatim, so the values are encoded before
   * they get there. Encoding the whole map - rather than only the names the pattern references -
   * keeps the keys identical, and reconstruct() throwing std::out_of_range on a missing variable is
   * behaviour worth preserving.
   */
  std::unordered_map<oatpp::String, oatpp::String> encodedArgs;
  for(auto& arg : args) {
    encodedArgs[arg.first] = utils::HttpSanitize::encodePathSegment(arg.second);
  }

  auto pattern = oatpp::web::url::mapping::Pattern::parse(m_endpoint->info()->path);
  auto path = pattern->reconstruct(encodedArgs, pathTail);

  utils::HttpSanitize::validateRequestTarget(path);
  return path;

}

EndpointTool::Headers EndpointTool::prepareEndpointHeaders(const std::unordered_map<oatpp::String, oatpp::String>& args, Error& error) const {

  Headers result;

  auto& info = *m_endpoint->info();

  for(auto& hp : info.headers.getOrder()) {
    auto& param = info.headers[hp];
    auto it = args.find(param.name);
    if(it != args.end()) {
      /*
       * The one place where encoding is not an option: there is no encoding for a header, and
       * stripping CR or LF would silently send a different header than the caller asked for.
       * Reject, and let the tool call fail.
       */
      utils::HttpSanitize::validateHeaderField(param.name, it->second);
      result.put(it->first, it->second);
    }
  }

  return result;

}

oatpp::Object<dto::Tool> EndpointTool::describe() const {

  auto tool = dto::Tool::createShared();

  tool->name = m_endpoint->info()->name;
  if(m_endpoint->info()->description) {
    tool->description = m_endpoint->info()->description;
  } else if(m_endpoint->info()->summary) {
    tool->description = m_endpoint->info()->summary;
  } else {
    tool->description = m_endpoint->info()->name;
  }

  tool->inputSchema = generateEndpointSchema();

  return tool;
}

oatpp::Object<dto::ServerResultToolsCall> EndpointTool::call(const oatpp::String& sessionId, const oatpp::Tree& args) {

  std::unordered_map<oatpp::String, oatpp::String> stringArgs;
  for(v_uint32 i = 0; i < (*args).getMap().size(); i ++) {
    auto pair = (*args).getMap()[i];
    stringArgs[pair.first] = pair.second.get().toString();
  }

  Error error;
  auto path = prepareEndpointPath(stringArgs, error);
  auto headers = prepareEndpointHeaders(stringArgs, error);

  OATPP_LOGi("EndpointTool::call", "method: {}, path: '{}'", m_endpoint->info()->method, path)
  for(auto& h : headers.getAll()) {
    OATPP_LOGi("EndpointTool::call", "Header: {}: '{}'", h.first.toString(), h.second.toString())
  }

  std::shared_ptr<oatpp::web::protocol::http::outgoing::Body> body;
  auto bodyIt = stringArgs.find(m_endpoint->info()->body.name);
  if(bodyIt != stringArgs.end()) {
    auto& bodyTree = args[m_endpoint->info()->body.name];
    oatpp::String content = bodyIt->second;
    if(bodyTree.isMap() || bodyTree.isPairs() || bodyTree.isVector()) {
      auto mapper = m_components.mappers->getDefaultMapper();
      if(!mapper) throw std::runtime_error("No default mapper found to serialize body. Try to sending body as serialized string instead of an object.");
      oatpp::Tree polymorph = bodyTree;
      content = mapper->writeToString(polymorph);
    }
    body = std::make_shared<oatpp::web::protocol::http::outgoing::BufferBody>(content, "application/json");
    OATPP_LOGd("[oatpp::mcp::capabilities::EndpointTool::call()]", "body content='{}'", content)
  }

  auto response = m_components.apiBridge->getHttpExecutor()->execute(
    m_endpoint->info()->method,
    path,
    headers,
    body,
    nullptr
  );

  if(!response) {
    auto result = dto::ServerResultToolsCall::createShared();
    result->content = {capabilities::Utils::createTextContent("Null response")};
    result->isError = true;
    return result;
  }

  oatpp::String bodyString = response->readBodyToString();

  oatpp::data::stream::BufferOutputStream ss(256);
  ss << "HTTP Response:\n";
  ss << "code: " << response->getStatusCode() << "\n";
  if(!bodyString->empty()) {
    oatpp::String contentType = response->getHeader("content-type").getValue("not set");
    ss << "content-type: " << contentType << "\n";
    ss << "body: " << bodyString;
  }

  auto result = dto::ServerResultToolsCall::createShared();
  result->content = {Utils::createTextContent(ss.toString())};
  return result;
}

}}}
