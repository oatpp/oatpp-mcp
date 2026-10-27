#include "ListenerMessageTest.hpp"

#include "TestChecks.hpp"

#include "oatpp-mcp/Listener.hpp"
#include "oatpp-mcp/event/Session.hpp"

#include <chrono>
#include <string>

namespace {

/** What the server owes the sender of a message. */
enum class Expectation {
  Nothing,       ///< must not crash; a reply is optional because the message carries no `id`
  Response,      ///< must be answered, with a result or with an error
  ErrorResponse  ///< must be answered with a JSON-RPC error object
};

struct Message {
  const char* payload;
  const char* description;
  Expectation expectation;
};

/*
 * Rows 1-12 are malformed input; each one used to abort the process. Rows 13-17 are controls that
 * pin the behaviour the crash fix must not break.
 */
static const Message kMessages[] = {

  {/*------------------------------------------------------------- not JSON at all --------*/
    "",
    "empty POST body (the disclosed PoC)",
    Expectation::Nothing
  },
  {
    "not json at all",
    "truncated garbage",
    Expectation::Nothing
  },
  {
    "null",
    "bare null",
    Expectation::Nothing
  },
  {
    "[1,2,3]",
    "bare array",
    Expectation::Nothing
  },

  {/*------------------------------------------------------- params of the wrong type -----*/
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":123}",
    "params is a number",
    Expectation::ErrorResponse
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":[1]}",
    "params is an array",
    Expectation::ErrorResponse
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":\"str\"}",
    "params is a string",
    Expectation::ErrorResponse
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":123}}",
    "params.name is a number",
    Expectation::ErrorResponse
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"getUserById\",\"arguments\":5}}",
    "arguments is a number",
    Expectation::ErrorResponse
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":123}",
    "method is a number",
    Expectation::ErrorResponse
  },

  {/*----------------------------------------------------------- missing params -----------*/
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
    "tools/call without params",
    Expectation::ErrorResponse
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\"}",
    "prompts/get without params",
    Expectation::ErrorResponse
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":123}}",
    "resources/read with a numeric uri",
    Expectation::ErrorResponse
  },

  {/*----------------------------------------------------------------- controls -----------*/
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
    "tools/list is answered (control)",
    Expectation::Response
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}",
    "ping is answered (control)",
    Expectation::Response
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/templates/list\"}",
    "resources/templates/list is answered (control)",
    Expectation::Response
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"definitely/not/a/method\"}",
    "unknown method is reported, not ignored",
    Expectation::ErrorResponse
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"definitely-not-a-tool\"}}",
    "unknown tool is answered (control)",
    Expectation::Response
  },

};

}

void oatpp::mcp::test::ListenerMessageTest::onRun() {

  Checks checks("TEST[mcp::ListenerMessage]");

  oatpp::mcp::Listener listener;

  for(const auto& message : kMessages) {

    /*
     * A session that is not attached to event::Server: no thread, no pinger, nothing to clean up.
     * onEvent() is the unit under test.
     */
    oatpp::mcp::event::Session session;

    oatpp::mcp::event::Event event;
    event.name = "post";
    event.data = message.payload;

    std::string thrown;
    try {
      listener.onEvent(session, event);
    } catch (const std::exception& e) {
      thrown = e.what();
    } catch (...) {
      thrown = "unknown exception";
    }

    checks.check(thrown.empty(),
                 std::string("no exception escapes onEvent(): ") + message.description,
                 "thrown: " + thrown + " | payload: '" + escape(message.payload) + "'");

    if(!thrown.empty()) {
      continue;
    }

    if(message.expectation == Expectation::Nothing) {
      continue;
    }

    auto reply = session.getOutStream()->read(std::chrono::milliseconds(100));

    checks.check(static_cast<bool>(reply),
                 std::string("a reply was produced for: ") + message.description,
                 "payload: '" + escape(message.payload) + "'");

    if(!reply) {
      continue;
    }

    if(message.expectation == Expectation::ErrorResponse) {
      checks.check(str(reply.data).find("\"error\"") != std::string::npos,
                   std::string("the reply is an error for: ") + message.description,
                   "reply: " + escape(str(reply.data)));
    }
  }

  checks.assertNoFailures();
}
