#include "ListenerMessageTest.hpp"

#include "LogCapture.hpp"
#include "TestChecks.hpp"

#include "oatpp-mcp/Listener.hpp"
#include "oatpp-mcp/capabilities/Tool.hpp"
#include "oatpp-mcp/capabilities/Utils.hpp"
#include "oatpp-mcp/event/Session.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

using oatpp::mcp::test::CapturingLogger;
using oatpp::mcp::test::ScopedLogger;
using oatpp::mcp::test::describe;
using oatpp::mcp::test::withTag;

namespace {

/**
 * An event listener that throws.
 *
 * `EventListener` is an extension point, so application code that throws is a thing that happens.
 * What matters is where the exception lands: `Session::listen()` runs on a detached thread, and an
 * exception that reaches the top of a thread is std::terminate for the whole process - and short of
 * that, the session is never removed from its server's registry.
 */
class ThrowingListener : public oatpp::mcp::event::Session::EventListener {
public:

  std::atomic<v_int32> calls {0};

  void onEvent(oatpp::mcp::event::Session&, const oatpp::mcp::event::Event&) override {
    calls ++;
    throw std::runtime_error("deliberately thrown from a listener");
  }

};

/**
 * A capability registered with the listener.
 *
 * Without one every `tools/call` is answered with "unknown tool", so a test could not tell "the
 * parameters were rejected" apart from "the tool does not exist" - and the arguments check could be
 * doing nothing at all. This records whether it ran.
 */
class EchoTool : public oatpp::mcp::capabilities::Tool {
public:

  std::atomic<v_int32> calls {0};

  oatpp::Object<oatpp::mcp::dto::Tool> describe() const override {
    auto tool = oatpp::mcp::dto::Tool::createShared();
    tool->name = "echo";
    tool->description = "Records that it was called";
    return tool;
  }

  oatpp::Object<oatpp::mcp::dto::ServerResultToolsCall> call(const oatpp::String& /*sessionId*/,
                                                             const oatpp::Tree& /*args*/) override
  {
    calls ++;
    auto result = oatpp::mcp::dto::ServerResultToolsCall::createShared();
    result->content = { oatpp::mcp::capabilities::Utils::createTextContent("echo") };
    result->isError = false;
    return result;
  }

};

/** What the server owes the sender of a message. */
enum class Expectation {
  Nothing,       ///< must not crash; a reply is optional because the message carries no `id`
  NoResponse,    ///< must NOT be answered - a notification must never get a response
  Response,      ///< must be answered, with a result or with an error
  ErrorResponse  ///< must be answered with a JSON-RPC error object
};

struct Message {
  const char* payload;
  const char* description;
  Expectation expectation;
  /** Expected invocations of the registered `echo` tool; -1 = not checked. */
  int echoCalls = -1;
  /**
   * Expected JSON-RPC error code; 0 = any error is fine.
   *
   * Pinning the code, and not just the presence of an error, is what keeps the taxonomy honest:
   * "-32602 from the handler's remap" and "-32600 from the envelope" both contain `"error"`, and a
   * test that cannot tell them apart cannot tell that a layer of the fix was removed.
   */
  int expectedCode = 0;
};

/*
 * Rows 1-12 are malformed input; each one used to abort the process. Rows 13-17 are controls that
 * pin the behaviour the crash fix must not break.
 */
static const Message kMessages[] = {

  {/*------------------------------------------------------------- not JSON at all --------*/
    /*
     * Nothing could be read, so these are answered with a null id (JSON-RPC 2.0 §5) rather than
     * silently dropped: a client that sent a message with a typo in it should hear about it.
     */
    "",
    "empty POST body (the disclosed PoC)",
    Expectation::ErrorResponse,
    -1,
    -32700
  },
  {
    "not json at all",
    "truncated garbage",
    Expectation::ErrorResponse,
    -1,
    -32700
  },
  {
    "null",
    "bare null",
    Expectation::ErrorResponse,
    -1,
    -32600
  },
  {
    "[1,2,3]",
    "bare array",
    Expectation::ErrorResponse,
    -1,
    -32600
  },

  {/*------------------------------------------------------- params of the wrong type -----*/
    /*
     * Rejected by the envelope, before any method runs: the request itself is not well-formed, and
     * that is a different answer from "the parameters do not fit this method".
     */
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":123}",
    "params is a number",
    Expectation::ErrorResponse,
    -1,
    -32600
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":[1]}",
    "params is an array",
    Expectation::ErrorResponse,
    -1,
    -32600
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":\"str\"}",
    "params is a string",
    Expectation::ErrorResponse,
    -1,
    -32600
  },
  {
    /* A well-formed envelope whose params do not fit the method: the handler's problem, -32602. */
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":123}}",
    "params.name is a number",
    Expectation::ErrorResponse,
    -1,
    -32602
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"getUserById\",\"arguments\":5}}",
    "arguments is a number",
    Expectation::ErrorResponse,
    -1,
    -32602
  },
  {
    /*
     * The same against a tool that exists: a scalar `arguments` must be refused as a malformed
     * request, and the capability must not be handed something it will index as a map. Note the
     * expectation is a JSON-RPC *error*, not an isError tool result - the difference is whether the
     * request or the tool is at fault, and the serialized forms are distinguishable.
     */
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":5}}",
    "arguments of the wrong type never reach the tool",
    Expectation::ErrorResponse,
    0,
    -32602
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":123}",
    "method is a number",
    Expectation::ErrorResponse,
    -1,
    -32600
  },
  {
    /* An id has to be echoable as a scalar; an object is not one, and must not be reflected. */
    "{\"jsonrpc\":\"2.0\",\"id\":{\"nested\":1},\"method\":\"tools/list\"}",
    "id is an object",
    Expectation::ErrorResponse,
    -1,
    -32600
  },

  {/*----------------------------------------------------------- missing params -----------*/
    /* An absent `params` is legal JSON-RPC; the required field inside it is not. */
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
    "tools/call without params",
    Expectation::ErrorResponse,
    -1,
    -32602
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\"}",
    "prompts/get without params",
    Expectation::ErrorResponse,
    -1,
    -32602
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":123}}",
    "resources/read with a numeric uri",
    Expectation::ErrorResponse,
    -1,
    -32602
  },

  {/*--------------------------------------------- every handler wraps its own remap ------*/
    /*
     * One row per method, because each handler wraps its own parameter remap: a test that exercises
     * only tools/call leaves six of them free to throw, and the whole point of the fix is that no
     * path through a handler may escape to the thread.
     */
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\",\"params\":{\"name\":123}}",
    "prompts/get with a numeric name",
    Expectation::ErrorResponse, -1, -32602
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"cursor\":123}}",
    "tools/list with a numeric cursor",
    Expectation::ErrorResponse, -1, -32602
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/list\",\"params\":{\"cursor\":123}}",
    "prompts/list with a numeric cursor",
    Expectation::ErrorResponse, -1, -32602
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\",\"params\":{\"cursor\":123}}",
    "resources/list with a numeric cursor",
    Expectation::ErrorResponse, -1, -32602
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/templates/list\",\"params\":{\"cursor\":123}}",
    "resources/templates/list with a numeric cursor",
    Expectation::ErrorResponse, -1, -32602
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":123}}",
    "initialize with a numeric protocolVersion",
    Expectation::ErrorResponse, -1, -32602
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
    /* initialize is the first call a real client makes; it must survive being given nothing. */
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}",
    "initialize is answered (control)",
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
    Expectation::ErrorResponse,
    -1,
    -32601
  },
  {
    /* A notification: no id, so nothing may come back - not even -32601. */
    "{\"jsonrpc\":\"2.0\",\"method\":\"definitely/not/a/method\"}",
    "unknown method with no id is a notification: no reply",
    Expectation::NoResponse
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"definitely-not-a-tool\"}}",
    "unknown tool is answered (control)",
    Expectation::ErrorResponse,
    -1,
    -32602
  },
  {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"k\":\"v\"}}}",
    "a registered tool runs on well-formed arguments (control)",
    Expectation::Response,
    1
  },
  {
    /*
     * Absent is not the same as wrong: a capability that takes no arguments is called without the
     * field, and refusing that would break every such tool.
     */
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"}}",
    "a registered tool runs with no arguments field at all (control)",
    Expectation::Response,
    1
  },

};

}

void oatpp::mcp::test::ListenerMessageTest::onRun() {

  Checks checks("TEST[mcp::ListenerMessage]");

  oatpp::mcp::Listener listener;
  auto echo = std::make_shared<EchoTool>();
  listener.addTool(echo);

  for(const auto& message : kMessages) {

    /*
     * A session that is not attached to event::Server: no thread, no pinger, nothing to clean up.
     * onEvent() is the unit under test.
     */
    oatpp::mcp::event::Session session;

    oatpp::mcp::event::Event event;
    event.name = "post";
    event.data = message.payload;

    echo->calls = 0;   // each row is judged on its own message, not cumulatively

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

    if(message.echoCalls >= 0) {
      auto actual = echo->calls.load();
      checks.check(actual == message.echoCalls,
                   std::string("the tool ran the expected number of times for: ") + message.description,
                   "calls=" + std::to_string(actual) + ", expected=" + std::to_string(message.echoCalls));
    }

    if(!thrown.empty()) {
      continue;
    }

    if(message.expectation == Expectation::Nothing) {
      continue;
    }

    auto reply = session.getOutStream()->read(
      std::chrono::milliseconds(message.expectation == Expectation::NoResponse ? 50 : 100));

    if(message.expectation == Expectation::NoResponse) {
      /*
       * JSON-RPC 2.0 §4.1: a Notification is a request without an id, and the server MUST NOT
       * reply to it. Answering one leaves the client matching a response against a request it never
       * made - which is why "unknown method" cannot simply always answer -32601.
       */
      checks.check(!static_cast<bool>(reply),
                   std::string("nothing was answered to the notification: ") + message.description,
                   "reply: " + escape(str(reply.data)));
      continue;
    }

    checks.check(static_cast<bool>(reply),
                 std::string("a reply was produced for: ") + message.description,
                 "payload: '" + escape(message.payload) + "'");

    if(!reply) {
      continue;
    }

    if(message.expectation == Expectation::Response) {
      /*
       * "A reply came back" is not enough: an error is a reply too, and every control row would
       * pass while the server answered them all with -32602. A control is a *result*.
       */
      auto replyText = str(reply.data);
      checks.check(replyText.find("\"result\"") != std::string::npos,
                   std::string("the reply is a result for: ") + message.description,
                   "reply: " + escape(replyText));
      continue;
    }

    if(message.expectation == Expectation::ErrorResponse) {
      auto replyText = str(reply.data);
      checks.check(replyText.find("\"error\"") != std::string::npos,
                   std::string("the reply is an error for: ") + message.description,
                   "reply: " + escape(replyText));

      if(message.expectedCode != 0) {
        /* Compacted, so the check does not depend on whether the mapper is beautifying. */
        auto compact = replyText;
        compact.erase(std::remove_if(compact.begin(), compact.end(),
                                     [](unsigned char c) { return c == ' ' || c == '\n'; }),
                      compact.end());
        auto needle = "\"code\":" + std::to_string(message.expectedCode);
        checks.check(compact.find(needle) != std::string::npos,
                     std::string("the reply carries code ") + std::to_string(message.expectedCode) +
                       " for: " + message.description,
                     "expected " + needle + " in: " + escape(compact));
      }
    }
  }

  /*--------------------------------------------------------------- layer 3: the thread ----*/
  {
    /*
     * The last line of defence, and the only one that cannot be tested by calling onEvent(): it is
     * about the thread that calls it. Three messages, each of which makes the listener throw - if
     * the third is delivered, the loop survived the first two.
     */
    oatpp::mcp::event::Session session;
    auto throwing = std::make_shared<ThrowingListener>();

    std::thread running([&]{ session.listen(throwing); });

    const v_int32 rounds = 3;
    for(v_int32 i = 1; i <= rounds; i++) {

      oatpp::mcp::event::Event event;
      event.name = "post";
      event.data = "{}";
      session.getInStream()->post(event);

      auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
      while(throwing->calls.load() < i && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
    }

    checks.check(throwing->calls.load() == rounds,
                 "a listener that throws does not stop the session thread reading",
                 "messages delivered=" + std::to_string(throwing->calls.load()) + " of " + std::to_string(rounds));
    checks.check(session.isOpen(), "the session is still open after a listener threw");

    session.close();
    running.join();
  }

  /*--------------------------------------------------- a reply with nowhere to go ---------*/
  {
    /*
     * The outbound direction has no HTTP status code to carry the news. When the session's out stream
     * will not take a reply, the log is the only record that the server did the work and could not
     * deliver it - and "the server ignored a valid call" is otherwise indistinguishable from "the
     * client hung up". (Finding F8; the inbound direction tells the sender instead - see
     * SseBackpressureTest.)
     */
    oatpp::mcp::event::Session session;
    session.getOutStream()->close();

    auto capture = std::make_shared<CapturingLogger>();
    {
      ScopedLogger scope(capture);

      oatpp::mcp::event::Event event;
      event.name = "post";
      event.data = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
      listener.onEvent(session, event);
    }

    auto mine = withTag(capture->records(), "Listener");
    checks.check(!mine.empty(),
                 "a reply that could not be queued is reported to the log",
                 "captured: " + describe(capture->records()));
    checks.check(!mine.empty()
                   && mine.front().message.find("could not be queued") != std::string::npos,
                 "and says that a reply was lost",
                 "captured: " + describe(capture->records()));
    checks.check(!mine.empty() && mine.front().message.find("stream closed") != std::string::npos,
                 "and why it was lost",
                 "captured: " + describe(capture->records()));
  }

  checks.assertNoFailures();
}
