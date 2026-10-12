//
// Created by Leonid S on 12/8/24.
//

#ifndef OATPP_MCP_SSE_CONTROLLER_HPP
#define OATPP_MCP_SSE_CONTROLLER_HPP

#include "ReadCallback.hpp"

#include "oatpp-mcp/event/Server.hpp"
#include "oatpp-mcp/utils/AccessGuard.hpp"
#include "oatpp-mcp/utils/LogSafe.hpp"

#include "oatpp/web/protocol/http/outgoing/StreamingBody.hpp"
#include "oatpp/web/server/api/ApiController.hpp"

#include "oatpp/base/Log.hpp"
#include "oatpp/macro/codegen.hpp"
#include "oatpp/macro/component.hpp"

#include OATPP_CODEGEN_BEGIN(ApiController) //<-- Begin Codegen

namespace oatpp { namespace mcp { namespace sse {

class Controller : public oatpp::web::server::api::ApiController {
private:
  std::shared_ptr<event::Server> m_server;
  std::shared_ptr<event::Session::EventListener> m_eventListener;
  utils::AccessGuard m_access;
private:

  /**
   * Apply the access policy to one request.
   *
   * Both endpoints go through here, so "the SSE endpoints check Origin and Host" is a property of
   * the class rather than of the two places somebody remembered to write it - see
   * SECURITY-FINDINGS.md, finding F4.
   *
   * @param request - the incoming request.
   * @param endpoint - what to call it in the log.
   * @return @c nullptr when the request may proceed, otherwise the response to return to it.
   */
  std::shared_ptr<OutgoingResponse> reject(const std::shared_ptr<IncomingRequest>& request,
                                           const char* endpoint)
  {
    auto origin = request->getHeader("Origin");
    auto host = request->getHeader("Host");

    auto decision = m_access.check(origin, host);
    if(decision.allowed) {
      return nullptr;
    }

    /*
     * The values are logged, the response only carries the rule: a refusal that repeats the
     * rejected header tells an attacker they had the right idea, and puts caller text into the
     * operator's log unrendered.
     */
    OATPP_LOGw("[oatpp::mcp::sse::Controller]",
               "Warning - rejected {}: {} (origin='{}', host='{}')",
               endpoint,
               utils::LogSafe::text(decision.reason),
               utils::LogSafe::headerValue("Origin", origin),
               utils::LogSafe::text(host))

    return createResponse(decision.status, decision.reason);
  }

public:

  Controller(const std::shared_ptr<event::Server>& mcpServer,
             const std::shared_ptr<event::Session::EventListener>& eventListener,
             OATPP_COMPONENT(std::shared_ptr<oatpp::web::mime::ContentMappers>, apiContentMappers),
             const oatpp::String& apiPrefix = nullptr,
             const utils::AccessGuard::Config& access = utils::AccessGuard::Config())
    : oatpp::web::server::api::ApiController(apiContentMappers, apiPrefix)
    , m_server(mcpServer)
    , m_eventListener(eventListener)
    , m_access(access)
  {}

public:

  ENDPOINT("GET", "sse", sse,
           REQUEST(std::shared_ptr<IncomingRequest>, request))
  {
    if(auto refusal = reject(request, "GET sse")) {
      return refusal;
    }

    auto session = m_server->startNewSession(m_eventListener);
    if(!session) {
      /*
       * The server is full. 503 rather than a session that cannot be served: the client is asked to
       * come back, and nothing is quietly dropped on the floor.
       */
      OATPP_LOGw("[oatpp::mcp::sse::Controller]", "Warning - no session available for a new client")
      return createResponse(Status::CODE_503, "Too many sessions");
    }

    auto body = std::make_shared<oatpp::web::protocol::http::outgoing::StreamingBody>
      (std::make_shared<ReadCallback>(session, m_routerPrefix));

    auto response = OutgoingResponse::createShared(Status::CODE_200, body);
    response->putHeader("Cache-Control", "no-store");
    response->putHeader("Content-Type", "text/event-stream");

    return response;
  }

  ENDPOINT("POST", "sessions/{sessionId}", mcpPost,
           PATH(String, sessionId),
           BODY_STRING(String, body),
           REQUEST(std::shared_ptr<IncomingRequest>, request))
  {
    if(auto refusal = reject(request, "POST sessions")) {
      return refusal;
    }

    auto session = m_server->getSession(sessionId);
    if(!session) {
      /*
       * Used to answer 200 "OK", which made a probe for a session identifier indistinguishable from
       * a delivered message - and left a hijacking attempt with nothing to show the operator. The
       * body says no more than that: whether an identifier was once valid is the server's business.
       */
      OATPP_LOGw("[oatpp::mcp::sse::Controller]",
                 "Warning - no session to deliver to: {}",
                 utils::LogSafe::text(sessionId))
      return createResponse(Status::CODE_404, "No such session");
    }

    auto stream = session->getInStream();
    event::Event event;
    event.name = "post";
    event.data = body;

    switch(stream->post(event)) {

      case event::PostResult::Queued:
        return createResponse(Status::CODE_200, "OK");

      case event::PostResult::DroppedClosed:
        /*
         * The session was closed between the lookup above and the post. It gets the same answer as
         * an identifier that never existed: "this one used to work" is not something the transport
         * needs to know, and it is exactly what somebody probing for live sessions wants to learn.
         */
        return createResponse(Status::CODE_404, "No such session");

      case event::PostResult::DroppedFull:
        break;
    }

    /*
     * Alive, and not reading. Answering 200 here would be a claim about a message that had already
     * been thrown away, and the sender would wait for a response to a call the server never took -
     * which is the failure this exchange exists to make visible. 503 with a Retry-After says what
     * is actually true: not now.
     */
    OATPP_LOGw("[oatpp::mcp::sse::Controller]",
               "Warning - session {} is not reading; refused a message of {} bytes",
               session->getId(),
               body ? body->size() : 0)

    auto refused = createResponse(Status::CODE_503, "Session is not reading");
    refused->putHeader("Retry-After", "1");
    return refused;
  }

};

}}}

#include OATPP_CODEGEN_END(ApiController) //<-- End Codegen

#endif //OATPP_MCP_SSE_CONTROLLER_HPP
