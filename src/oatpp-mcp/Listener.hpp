//
// Created by Leonid S on 12/8/24.
//

#ifndef OATPP_MCP_LISTENER_HPP
#define OATPP_MCP_LISTENER_HPP

#include "dto/JsonRpc.hpp"
#include "dto/Methods.hpp"

#include "capabilities/Prompt.hpp"
#include "capabilities/Tool.hpp"
#include "capabilities/Resource.hpp"

#include "event/Session.hpp"
#include "oatpp/json/ObjectMapper.hpp"
#include "oatpp/data/mapping/ObjectRemapper.hpp"

namespace oatpp { namespace mcp {

class Pinger : public event::Session::Pinger {
private:
  std::atomic<v_uint64> m_pingId;
  oatpp::json::ObjectMapper m_mapper;
public:
  Pinger();
  void onPing(event::Session& session) override;
};

class Listener : public event::Session::EventListener {
private:
  oatpp::json::ObjectMapper m_mapper;
  oatpp::data::mapping::ObjectRemapper m_remapper;
private:
  void sendRpcResult(event::Session& session, const oatpp::Object<dto::RpcResult>& result);
  /**
   * Answer with a JSON-RPC error object.
   * @param id - the identifier to echo, or @c nullptr when the message did not carry one that
   *        could be read. JSON-RPC requires the error to be sent with a null id in exactly that
   *        case, which is why this takes an id rather than the call.
   * @param code - a JSON-RPC 2.0 error code, see §5.1.
   * @param message - a short, generic, client-facing description.
   */
  void sendRpcError(event::Session& session, const oatpp::Any& id, v_int32 code,
                    const oatpp::String& message);
  /**
   * Answer <c>-32602 Invalid params</c> for one method.
   * @param method - the method name, for the log.
   * @param detail - why the parameters were rejected, for the log. It is deliberately not sent:
   *        mapper internals in a client-facing message describe the implementation and buy an
   *        attacker nothing else.
   */
  void sendInvalidParams(event::Session& session, const oatpp::Object<dto::RpcCall>& call,
                         const char* method, const char* detail);
  /**
   * Validate the JSON-RPC envelope of one message and dispatch it.
   *
   * Split out of {@link onEvent()} so that the outermost catch has one obvious job: nothing that
   * this function does not already answer may reach the session thread. See SECURITY-FINDINGS.md,
   * finding F3.
   */
  void handleCall(event::Session& session, const event::Event& event);
  oatpp::Object<dto::ServerCapabilities> getServerCapabilities();
private:
  void resourcesList(event::Session& session, const oatpp::Object<dto::RpcCall>& call);
  void resourceTemplatesList(event::Session& session, const oatpp::Object<dto::RpcCall>& call);
  void resourcesRead(event::Session& session, const oatpp::Object<dto::RpcCall>& call);
  void promptsGet(event::Session& session, const oatpp::Object<dto::RpcCall>& call);
  void promptsList(event::Session& session, const oatpp::Object<dto::RpcCall>& call);
  void toolsCall(event::Session& session, const oatpp::Object<dto::RpcCall>& call);
  void toolsList(event::Session& session, const oatpp::Object<dto::RpcCall>& call);
  void onInitialize(event::Session& session, const oatpp::Object<dto::RpcCall>& call);
private:
  void onPing(event::Session& session, const oatpp::Object<dto::RpcCall>& call);
private:
  std::unordered_map<oatpp::String, std::shared_ptr<capabilities::Prompt>> m_prompts;
  std::unordered_map<oatpp::String, std::shared_ptr<capabilities::Tool>> m_tools;
  capabilities::Resource::Router m_resourceRouter;
  std::vector<std::shared_ptr<capabilities::Resource>> m_resources;
  std::vector<std::shared_ptr<capabilities::Resource>> m_resourceTemplates;
public:

  Listener();

  void addPrompt(const std::shared_ptr<capabilities::Prompt>& prompt);
  void addTool(const std::shared_ptr<capabilities::Tool>& tool);
  void addResource(const std::shared_ptr<capabilities::Resource>& resource);

  void onEvent(event::Session& session, const event::Event& event) override;

};

}}

#endif //MY_PROJECT_LISTENER_HPP
