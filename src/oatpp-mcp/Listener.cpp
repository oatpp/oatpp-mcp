//
// Created by Leonid S on 12/8/24.
//

#include "Listener.hpp"

#include "capabilities/Utils.hpp"
#include "utils/LogSafe.hpp"

#include "oatpp/utils/Conversion.hpp"
#include "oatpp/base/Log.hpp"

/*
 * Every value below that a remote client influenced - a message body, a method name, a tool name,
 * the text of an exception thrown while handling any of them - is rendered through
 * {@link oatpp::mcp::utils::LogSafe} before it reaches a log statement. Session identifiers are
 * server-generated and format-constrained, so they go as they are. See SECURITY-FINDINGS.md, F6.
 */

namespace {

/**
 * JSON-RPC 2.0 pre-defined error codes (§5.1). The range -32768..-32000 is reserved for exactly
 * this; a code this module invented would have to live outside it.
 */
namespace rpc_error {

  /** The message is not JSON at all. */
  constexpr v_int32 ParseError = -32700;

  /** JSON, but not a JSON-RPC 2.0 request object. */
  constexpr v_int32 InvalidRequest = -32600;

  /** Not a method this server offers. */
  constexpr v_int32 MethodNotFound = -32601;

  /** The parameters do not fit the method: missing, wrong type, or wrong shape. */
  constexpr v_int32 InvalidParams = -32602;

  /** A handler threw. */
  constexpr v_int32 InternalError = -32603;

}

/**
 * Is this an `arguments` node that a capability can be handed?
 *
 * Absent and null both mean "no arguments" - a capability that takes none is called without the
 * field, and that is not an error. Anything that is present and not an object is: a capability
 * indexes its arguments as a map, and handing it a number is how the process used to die.
 */
static bool isAbsentOrMap(const oatpp::Tree& arguments) {
  if(arguments == nullptr) {
    return true;
  }
  return arguments->isUndefined() || arguments->isNull() || arguments->isMap();
}

} // anonymous namespace

namespace oatpp { namespace mcp {

Pinger::Pinger()
  : m_pingId(0)
{
  m_mapper.serializerConfig().mapper.includeNullFields = false;
}

void Pinger::onPing(event::Session& session) {

  m_pingId ++;

  auto call = dto::RpcCall::createShared();
  call->id = "ping_" + oatpp::utils::Conversion::uint64ToStr(m_pingId);
  call->method = "ping";

  event::Event event;
  event.name = "message";
  event.data = m_mapper.writeToString(call);

  /*
   * A ping that cannot be queued means the client stopped reading - which the ping exists to find
   * out, and which is not this session's fault. Debug, not warning: the queue already logs a drop,
   * and a heartbeat fires every few seconds per session.
   */
  auto outcome = session.getOutStream()->post(event);
  if(!event::isQueued(outcome)) {
    OATPP_LOGd("Pinger", "[{}] ping not queued: {}", session.getId(), event::describe(outcome))
  }

}

Listener::Listener() {
  m_mapper.serializerConfig().mapper.includeNullFields = false;
  m_remapper.objectToTreeConfig().includeNullFields = false;
}

void Listener::addPrompt(const std::shared_ptr<capabilities::Prompt>& prompt) {
  auto description = prompt->describe();
  if(description && description->name && !description->name->empty()) {
    m_prompts[description->name] = prompt;
  }
}

void Listener::addTool(const std::shared_ptr<capabilities::Tool>& tool) {
  auto description = tool->describe();
  if(description && description->name && !description->name->empty()) {
    m_tools[description->name] = tool;
  }
}

void Listener::addResource(const std::shared_ptr<capabilities::Resource> &resource) {
  auto description = resource->describe();
  if(description) {
    if(description->uri && !description->uri->empty()) {
      m_resourceRouter.route(description->uri, resource);
      m_resources.push_back(resource);
    } else if(description->uriTemplate && !description->uriTemplate->empty()){
      m_resourceRouter.route(description->uriTemplate, resource);
      m_resourceTemplates.push_back(resource);
    } else {
      OATPP_LOGe("[oatpp::mcp::Listener::addResource()]", "Error - invalid resource description")
    }
  }
}

void Listener::sendRpcResult(event::Session& session, const oatpp::Object<dto::RpcResult>& result) {
  event::Event event;
  event.name = "message";
  event.data = m_mapper.writeToString(result);

  auto outcome = session.getOutStream()->post(event);
  if(!event::isQueued(outcome)) {
    /*
     * The work is done and the answer has nowhere to go. There is no second channel to this client,
     * so all it will notice is a timeout - and without this line, so does nobody else: "the server
     * ignored a valid call" and "the client stopped listening" used to look identical from here.
     *
     * What is logged is the size of the loss, not its content. A reply body is whatever the tool
     * read, and a lost reply is a transport fact - see SECURITY-FINDINGS.md, findings F6 and F8.
     */
    OATPP_LOGw("Listener",
               "[{}] reply could not be queued ({}) - {} bytes lost",
               session.getId(),
               event::describe(outcome),
               event.data ? event.data->size() : 0)
  }
}

void Listener::sendRpcError(event::Session& session, const oatpp::Any& id, v_int32 code,
                            const oatpp::String& message)
{
  auto rpcResult = dto::RpcResult::createShared();
  rpcResult->id = id;

  oatpp::data::mapping::Tree error;
  error["code"] = code;
  error["message"] = message;
  rpcResult->error = error;

  sendRpcResult(session, rpcResult);
}

void Listener::sendInvalidParams(event::Session& session, const oatpp::Object<dto::RpcCall>& call,
                                 const char* method, const char* detail)
{
  OATPP_LOGw("Listener", "[{}] rejected parameters for {}: {}", session.getId(), method,
             utils::LogSafe::text(detail))
  sendRpcError(session, call->id, rpc_error::InvalidParams, "Invalid params");
}

oatpp::Object<dto::ServerCapabilities> Listener::getServerCapabilities() {
  auto caps = dto::ServerCapabilities::createShared();
  if(!m_tools.empty()) {
    caps->tools = dto::CapabilityDeclaration::createShared();
    caps->tools->listChanged = true;
  }
  if(!m_resources.empty()) {
    caps->resources = dto::CapabilityDeclaration::createShared();
    caps->resources->listChanged = true;
  }
  if(!m_resourceTemplates.empty()) {
    caps->prompts = dto::CapabilityDeclaration::createShared();
    caps->prompts->listChanged = true;
  }
  return caps;
}

void Listener::promptsGet(event::Session& session, const oatpp::Object<dto::RpcCall>& call) {

  /*
   * Parameters are untrusted. Remapping them is the step that used to abort the process when the
   * caller sent the wrong shape, so it is inside the error handling rather than outside it.
   */
  oatpp::Object<dto::ClientParamsPromptsCall> callParams;
  try {
    callParams = m_remapper.remap<oatpp::Object<dto::ClientParamsPromptsCall>>(call->params);
  } catch (const std::exception& e) {
    sendInvalidParams(session, call, "prompts/get", e.what());
    return;
  }

  if(callParams->name == nullptr) {
    sendInvalidParams(session, call, "prompts/get", "'name' is required");
    return;
  }

  if(!isAbsentOrMap(callParams->arguments)) {
    sendInvalidParams(session, call, "prompts/get", "'arguments' must be an object");
    return;
  }

  auto rpcResult = dto::RpcResult::createShared();
  rpcResult->id = call->id;

  auto it = m_prompts.find(callParams->name);

  if(it != m_prompts.end()) {
    try {
      auto result = it->second->call(session.getId(), callParams->arguments);
      rpcResult->result = m_remapper.remap<oatpp::Tree>(result);
    } catch (const std::exception& e) {
      /* The detail is logged, not sent: see sendInvalidParams(). */
      OATPP_LOGe("[oatpp::mcp::Listener::promptsGet()]", "Error - prompt handler threw: {}",
                 utils::LogSafe::text(e.what()))
      oatpp::data::mapping::Tree error;
      error["code"] = rpc_error::InternalError;
      error["message"] = "Internal error";
      rpcResult->error = error;
    } catch (...) {
      OATPP_LOGe("[oatpp::mcp::Listener::promptsGet()]", "Error - prompt handler threw an unknown exception")
      oatpp::data::mapping::Tree error;
      error["code"] = rpc_error::InternalError;
      error["message"] = "Internal error";
      rpcResult->error = error;
    }
  } else {
    oatpp::data::mapping::Tree error;
    error["code"] = rpc_error::InvalidParams;
    error["message"] = "Unknown tool: invalid_prompt_name";
    rpcResult->error = error;
  }

  sendRpcResult(session, rpcResult);

}

void Listener::promptsList(event::Session& session, const oatpp::Object<dto::RpcCall>& call) {

  auto rpcResult = dto::RpcResult::createShared();
  rpcResult->id = call->id;

  /* The remap type-checks the one optional parameter (`cursor`); the value itself is unused. */
  try {
    m_remapper.remap<oatpp::Object<dto::ClientParamsToolsList>>(call->params);
  } catch (const std::exception& e) {
    sendInvalidParams(session, call, "prompts/list", e.what());
    return;
  }

  auto result = dto::ServerResultPromptsList::createShared();
  result->prompts = {};
  for(auto& p : m_prompts) {
    result->prompts->push_back(p.second->describe());
  }

  rpcResult->result = m_remapper.remap<oatpp::Tree>(result);
  sendRpcResult(session, rpcResult);

}

void Listener::toolsCall(event::Session& session, const oatpp::Object<dto::RpcCall>& call) {

  oatpp::Object<dto::ClientParamsToolsCall> callParams;
  try {
    callParams = m_remapper.remap<oatpp::Object<dto::ClientParamsToolsCall>>(call->params);
  } catch (const std::exception& e) {
    sendInvalidParams(session, call, "tools/call", e.what());
    return;
  }

  if(callParams->name == nullptr) {
    sendInvalidParams(session, call, "tools/call", "'name' is required");
    return;
  }

  /*
   * A tool indexes its arguments as a map, so a scalar there is not a tool failure waiting to be
   * caught further down - it is the request being malformed, and it is answered as one.
   */
  if(!isAbsentOrMap(callParams->arguments)) {
    sendInvalidParams(session, call, "tools/call", "'arguments' must be an object");
    return;
  }

  auto rpcResult = dto::RpcResult::createShared();
  rpcResult->id = call->id;

  auto it = m_tools.find(callParams->name);

  if(it != m_tools.end()) {

    try {
      auto result = it->second->call(session.getId(), callParams->arguments);
      rpcResult->result = m_remapper.remap<oatpp::Tree>(result);
    } catch (const std::exception& e) {
      /*
       * The exception text goes to the log, not to the client. A tool's own failure message is a
       * different thing and should reach the model - it belongs in an isError result the tool
       * builds itself, not in whatever an exception happened to carry.
       */
      OATPP_LOGe("[oatpp::mcp::Listener::toolsCall()]", "Error - tool '{}' threw: {}",
                 utils::LogSafe::text(callParams->name), utils::LogSafe::text(e.what()))
      auto result = dto::ServerResultToolsCall::createShared();
      result->isError = true;
      result->content = {
        capabilities::Utils::createTextContent("Tool handler thrown an exception")
      };
      rpcResult->result = m_remapper.remap<oatpp::Tree>(result);
    } catch (...) {
      OATPP_LOGe("[oatpp::mcp::Listener::toolsCall()]", "Error - tool '{}' threw an unknown exception",
                 utils::LogSafe::text(callParams->name))
      auto result = dto::ServerResultToolsCall::createShared();
      result->isError = true;
      result->content = {
        capabilities::Utils::createTextContent("Tool handler thrown an unknown exception")
      };
      rpcResult->result = m_remapper.remap<oatpp::Tree>(result);
    }

  } else {
    oatpp::data::mapping::Tree error;
    error["code"] = rpc_error::InvalidParams;
    error["message"] = "Unknown tool: invalid_tool_name";
    rpcResult->error = error;
  }

  sendRpcResult(session, rpcResult);

}

void Listener::toolsList(event::Session& session, const oatpp::Object<dto::RpcCall>& call) {

  auto rpcResult = dto::RpcResult::createShared();
  rpcResult->id = call->id;

  try {
    m_remapper.remap<oatpp::Object<dto::ClientParamsToolsList>>(call->params);
  } catch (const std::exception& e) {
    sendInvalidParams(session, call, "tools/list", e.what());
    return;
  }

  auto result = dto::ServerResultToolsList::createShared();
  result->tools = {};
  for(auto& p : m_tools) {
    result->tools->push_back(p.second->describe());
  }

  rpcResult->result = m_remapper.remap<oatpp::Tree>(result);
  sendRpcResult(session, rpcResult);

}

void Listener::onInitialize(event::Session& session, const oatpp::Object<dto::RpcCall>& call) {

  auto rpcResult = dto::RpcResult::createShared();
  rpcResult->id = call->id;

  try {
    m_remapper.remap<oatpp::Object<dto::ClientParamsInitialize>>(call->params);
  } catch (const std::exception& e) {
    sendInvalidParams(session, call, "initialize", e.what());
    return;
  }
  // TODO save client capabilities

  auto result = dto::ServerResultInitialize::createShared();
  result->protocolVersion = "2024-11-05";
  result->capabilities = getServerCapabilities();
  result->serverInfo = dto::ServerInfo::createShared();
  result->serverInfo->name = "Oat++ MCP Server";
  result->serverInfo->version = "0.0.1";

  rpcResult->result = m_remapper.remap<oatpp::Tree>(result);
  sendRpcResult(session, rpcResult);

}

void Listener::onPing(event::Session& session, const oatpp::Object<dto::RpcCall>& call) {
  auto rpcResult = dto::RpcResult::createShared();
  rpcResult->id = call->id;

  /* An empty object, built rather than reached through the field: `result` is only guaranteed to
   * be there by the DTO codegen, and a ping is not worth a null dereference over. */
  oatpp::data::mapping::Tree empty;
  empty.setMap({});
  rpcResult->result = empty;

  sendRpcResult(session, rpcResult);
}

void Listener::resourcesList(event::Session& session, const oatpp::Object<dto::RpcCall>& call) {
  auto rpcResult = dto::RpcResult::createShared();
  rpcResult->id = call->id;

  try {
    m_remapper.remap<oatpp::Object<dto::ClientParamsResourceList>>(call->params);
  } catch (const std::exception& e) {
    sendInvalidParams(session, call, "resources/list", e.what());
    return;
  }

  auto result = dto::ServerResultResourceList::createShared();
  result->resources = {};
  for(auto& rt : m_resources) {
    result->resources->push_back(rt->describe());
  }

  rpcResult->result = m_remapper.remap<oatpp::Tree>(result);
  sendRpcResult(session, rpcResult);
}

void Listener::resourceTemplatesList(event::Session& session, const oatpp::Object<dto::RpcCall>& call) {
  auto rpcResult = dto::RpcResult::createShared();
  rpcResult->id = call->id;

  try {
    m_remapper.remap<oatpp::Object<dto::ClientParamsResourceList>>(call->params);
  } catch (const std::exception& e) {
    sendInvalidParams(session, call, "resources/templates/list", e.what());
    return;
  }

  auto result = dto::ServerResultResourceTemplatesList::createShared();
  result->resourceTemplates = {};
  for(auto& rt : m_resourceTemplates) {
    result->resourceTemplates->push_back(rt->describe());
  }

  rpcResult->result = m_remapper.remap<oatpp::Tree>(result);
  sendRpcResult(session, rpcResult);
}

void Listener::resourcesRead(event::Session& session, const oatpp::Object<dto::RpcCall>& call) {
  auto rpcResult = dto::RpcResult::createShared();
  rpcResult->id = call->id;

  oatpp::Object<dto::ClientParamsResourceRead> callParams;
  try {
    callParams = m_remapper.remap<oatpp::Object<dto::ClientParamsResourceRead>>(call->params);
  } catch (const std::exception& e) {
    sendInvalidParams(session, call, "resources/read", e.what());
    return;
  }

  if(callParams && callParams->uri) {
    auto route = m_resourceRouter.getRoute(callParams->uri);
    if (route) {

      try {
        auto result = route.getEndpoint()->call(session.getId(), route);
        rpcResult->result = m_remapper.remap<oatpp::Tree>(result);
      } catch (const std::exception& e) {
        OATPP_LOGe("[oatpp::mcp::Listener::resourcesRead()]", "Error - resource handler threw: {}",
                   utils::LogSafe::text(e.what()))
        oatpp::data::mapping::Tree error;
        error["code"] = rpc_error::InternalError;
        error["message"] = "Internal error";
        rpcResult->error = error;
      } catch (...) {
        OATPP_LOGe("[oatpp::mcp::Listener::resourcesRead()]", "Error - resource handler threw an unknown exception")
        oatpp::data::mapping::Tree error;
        error["code"] = rpc_error::InternalError;
        error["message"] = "Internal error";
        rpcResult->error = error;
      }

    } else {
      oatpp::data::mapping::Tree error;
      error["code"] = rpc_error::InvalidParams;
      error["message"] = "Resource not found: unknown_resource";
      rpcResult->error = error;
    }

  } else {
    oatpp::data::mapping::Tree error;
    error["code"] = rpc_error::InvalidParams;
    error["message"] = "Invalid resource URI";
    rpcResult->error = error;
  }

  sendRpcResult(session, rpcResult);
}

void Listener::handleCall(event::Session& session, const event::Event& event) {

  /*--------------------------------------------------------------------- 1. is it JSON? ----*/
  oatpp::Tree parsed;
  try {
    parsed = m_mapper.readFromString<oatpp::Tree>(event.data);
  } catch (const std::exception& e) {
    OATPP_LOGw("Listener", "[{}] undecodable message: {}", session.getId(),
               utils::LogSafe::text(e.what()))
    /* No id could be read, so the error goes out with a null id - JSON-RPC §5. */
    sendRpcError(session, nullptr, rpc_error::ParseError, "Parse error");
    return;
  }

  /*----------------------------------------------- 2. is it a JSON-RPC request object? ----*/
  if(parsed == nullptr || !parsed->isMap()) {
    /* `null` and `[1,2,3]` are valid JSON and are not requests. */
    OATPP_LOGw("Listener", "[{}] message is not a JSON object", session.getId())
    sendRpcError(session, nullptr, rpc_error::InvalidRequest,
                 "Invalid request: expected a JSON-RPC 2.0 object");
    return;
  }

  /*--------------------------------------------------------------- 3. the id, if any ------*/
  /*
   * Read before anything else that can fail, because every error below has to echo it. A String or
   * a Number; null means "there is nothing to answer"; anything else is not an identifier.
   */
  auto& idNode = (*parsed)["id"];
  oatpp::Any id;
  bool hasId = false;
  if(!idNode.isUndefined() && !idNode.isNull()) {
    if(!(idNode.isString() || idNode.isIntPrimitive() || idNode.isFloatPrimitive())) {
      OATPP_LOGw("Listener", "[{}] message id is neither a string nor a number", session.getId())
      sendRpcError(session, nullptr, rpc_error::InvalidRequest,
                   "Invalid request: 'id' must be a string or a number");
      return;
    }
    try {
      id = m_remapper.remap<oatpp::Any>(idNode);
    } catch (const std::exception& e) {
      OATPP_LOGw("Listener", "[{}] unreadable message id: {}", session.getId(),
                 utils::LogSafe::text(e.what()))
      sendRpcError(session, nullptr, rpc_error::InvalidRequest,
                   "Invalid request: 'id' must be a string or a number");
      return;
    }
    hasId = true;
  }

  /*-------------------------------------------------------------------- 4. the method -----*/
  auto& methodNode = (*parsed)["method"];
  if(methodNode.isUndefined() || methodNode.isNull()) {
    sendRpcError(session, id, rpc_error::InvalidRequest, "Invalid request: 'method' is required");
    return;
  }
  if(!methodNode.isString()) {
    sendRpcError(session, id, rpc_error::InvalidRequest, "Invalid request: 'method' must be a string");
    return;
  }
  oatpp::String method = methodNode.getString();

  /*--------------------------------------------------------------------- 5. the params ----*/
  /*
   * Optional. JSON-RPC also allows positional arrays; MCP defines named parameters only, so an
   * array here is not a shape this server can answer.
   */
  auto& paramsNode = (*parsed)["params"];
  if(!paramsNode.isUndefined() && !paramsNode.isNull() && !paramsNode.isMap()) {
    sendRpcError(session, id, rpc_error::InvalidRequest,
                 "Invalid request: 'params' must be an object");
    return;
  }

  /*----------------------------------------------------- 6. the call, and its empty params --*/
  oatpp::Object<dto::RpcCall> call;
  try {
    call = m_remapper.remap<oatpp::Object<dto::RpcCall>>(parsed);
  } catch (const std::exception& e) {
    OATPP_LOGw("Listener", "[{}] message does not fit a JSON-RPC call: {}", session.getId(),
               utils::LogSafe::text(e.what()))
    sendRpcError(session, id, rpc_error::InvalidRequest, "Invalid request");
    return;
  }

  /* The validated id, not whatever the remap made of it. */
  call->id = id;

  /*
   * An absent `params` becomes an empty object. Remapping a missing node into a params DTO is one
   * of the things that used to abort the process, and every params field of every method here is
   * optional at the DTO level - the handler reports the ones a given method actually requires.
   */
  if(call->params == nullptr || call->params->isUndefined() || call->params->isNull()) {
    oatpp::data::mapping::Tree empty;
    empty.setMap({});
    call->params = empty;
  }

  /*----------------------------------------------------------------------- 7. dispatch ----*/
  if(method == "ping") {
    onPing(session, call);
  } else if(method == "initialize") {
    onInitialize(session, call);
  } else if(method == "tools/list") {
    toolsList(session, call);
  } else if(method == "tools/call") {
    toolsCall(session, call);
  } else if(method == "prompts/list") {
    promptsList(session, call);
  } else if(method == "prompts/get") {
    promptsGet(session, call);
  } else if(method == "resources/list") {
    resourcesList(session, call);
  } else if(method == "resources/read") {
    resourcesRead(session, call);
  } else if(method == "resources/templates/list") {
    resourceTemplatesList(session, call);
  } else if(hasId) {
    /*
     * A request must be answered, and until now an unknown method was a black hole: the client
     * waited for a reply that was never going to come. The method name is safe to echo - the JSON
     * serializer escapes control characters, so it cannot forge an SSE frame.
     */
    sendRpcError(session, id, rpc_error::MethodNotFound, oatpp::String("Method not found: ") + method);
  } else {
    /* A notification - no id, therefore nothing may be answered. */
    OATPP_LOGd("Listener", "[{}] ignored notification for unknown method: {}", session.getId(),
               utils::LogSafe::text(method))
  }

}

void Listener::onEvent(event::Session& session, const event::Event& event) {

  /*
   * The whole message, exactly as it arrived, at debug: this is the line an operator reads when a
   * client says the server ignored it. It is also the most attacker-shaped string in the process -
   * a message does not have to be valid JSON to reach here, and a newline in it used to appear as a
   * log record this server had written about a session it never had.
   */
  OATPP_LOGd("Event", "[{}] --> : {}", session.getId(),
             utils::LogSafe::text(event.data, utils::LogSafe::MaxMessageLength))

  /*
   * This runs on the session's own detached thread. An exception that leaves this function reaches
   * std::terminate and takes the whole process with it, and the input that causes it is one
   * unauthenticated POST away (SECURITY-FINDINGS.md, F3).
   *
   * Everything below already answers what it can; this catch is the last line, and it deliberately
   * does not reply. By this point there is no way to know whether a response was already sent for
   * the id, and a second response to the same id is a worse protocol violation than silence.
   */
  try {
    handleCall(session, event);
  } catch (const std::exception& e) {
    OATPP_LOGe("[oatpp::mcp::Listener::onEvent()]", "Error - unhandled exception while processing a "
               "message for session {}: {}", session.getId(), utils::LogSafe::text(e.what()))
  } catch (...) {
    OATPP_LOGe("[oatpp::mcp::Listener::onEvent()]", "Error - unknown exception while processing a "
               "message for session {}", session.getId())
  }

}

}}
