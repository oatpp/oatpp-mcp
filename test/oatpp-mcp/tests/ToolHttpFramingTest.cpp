#include "ToolHttpFramingTest.hpp"

#include "TestChecks.hpp"

#include "oatpp-mcp/capabilities/Tool.hpp"
#include "oatpp-mcp/dto/Methods.hpp"
#include "oatpp-mcp/utils/ApiBridge.hpp"
#include "oatpp-mcp/utils/JsonSchema.hpp"

#include "oatpp/json/ObjectMapper.hpp"
#include "oatpp/web/mime/ContentMappers.hpp"
#include "oatpp/web/protocol/http/Http.hpp"
#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/macro/codegen.hpp"
#include "oatpp/macro/component.hpp"

#include <atomic>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using oatpp::mcp::test::Checks;
using oatpp::mcp::test::escape;
using oatpp::mcp::test::str;

#include OATPP_CODEGEN_BEGIN(ApiController)

namespace {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The application that sits behind the MCP bridge
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Stands in for whatever an MCP server exposes as tools. Every handler records what arrived, so a
 * test can tell "the requested endpoint ran" apart from "some other endpoint ran as well" - which
 * is the distinction request smuggling is all about.
 */
class SpyController : public oatpp::web::server::api::ApiController {
private:
  std::mutex m_mutex;
  std::vector<std::string> m_seenUserIds;
  oatpp::String m_seenInjected;
public:

  std::atomic<v_int32> getUserByIdCalls;
  std::atomic<v_int32> createUserCalls;
  std::atomic<v_int32> getUsersCalls;
  std::atomic<v_int32> headeredCalls;

  SpyController(OATPP_COMPONENT(std::shared_ptr<oatpp::web::mime::ContentMappers>, contentMappers))
    : oatpp::web::server::api::ApiController(contentMappers)
    , getUserByIdCalls(0)
    , createUserCalls(0)
    , getUsersCalls(0)
    , headeredCalls(0)
  {}

  /** Path variable. A String rather than an Int32 so that the handler sees the raw value. */
  ENDPOINT("GET", "users/{userId}", getUserById, PATH(String, userId)) {
    getUserByIdCalls ++;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_seenUserIds.push_back(str(userId));
    return createResponse(oatpp::web::protocol::http::Status::CODE_200, "user");
  }

  ENDPOINT("POST", "users", createUser, BODY_STRING(String, body)) {
    createUserCalls ++;
    return createResponse(oatpp::web::protocol::http::Status::CODE_200, "created");
  }

  /** Query parameter - mirrors the demo UserController the disclosure's PoC was written against. */
  ENDPOINT("GET", "users/offset/{offset}/limit/{limit}/*", getUsers,
           PATH(UInt32, offset), PATH(UInt32, limit), QUERY(String, searchPhrase)) {
    getUsersCalls ++;
    return createResponse(oatpp::web::protocol::http::Status::CODE_200, "page");
  }

  /** Header parameter. */
  ENDPOINT("GET", "headered", headered,
           HEADER(String, xTest),
           REQUEST(std::shared_ptr<IncomingRequest>, request)) {
    headeredCalls ++;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_seenInjected = request->getHeader("X-Injected");
    return createResponse(oatpp::web::protocol::http::Status::CODE_200, "ok");
  }

  /* ---- what the upstream actually observed ---- */

  std::vector<std::string> seenUserIds() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_seenUserIds;
  }

  bool sawInjectedHeader() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_seenInjected != nullptr;
  }

  std::string injectedHeaderValue() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return str(m_seenInjected);
  }

  void reset() {
    getUserByIdCalls = 0;
    createUserCalls = 0;
    getUsersCalls = 0;
    headeredCalls = 0;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_seenUserIds.clear();
    m_seenInjected = nullptr;
  }

};

#include OATPP_CODEGEN_END(ApiController)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Harness
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Wires the spy controller into an ApiBridge and exposes one EndpointTool per endpoint, by tool
 * name - the same thing `oatpp::mcp::Server::addEndpoints()` does.
 */
class Fixture {
public:
  std::shared_ptr<SpyController> spy;
  std::shared_ptr<oatpp::mcp::utils::ApiBridge> bridge;
  std::unordered_map<std::string, std::shared_ptr<oatpp::mcp::capabilities::EndpointTool>> tools;
private:
  std::shared_ptr<oatpp::json::ObjectMapper> m_mapper;
public:

  Fixture() {
    auto json = std::make_shared<oatpp::json::ObjectMapper>();
    auto mappers = std::make_shared<oatpp::web::mime::ContentMappers>();
    mappers->putMapper(json);
    mappers->setDefaultMapper("application/json");

    spy = std::make_shared<SpyController>(mappers);

    /*
     * ApiBridge serves the endpoints over the shared virtual interface "mcp.bridge.virtualhost" -
     * one bridge per process, which is why each test also runs in its own process. It cannot be
     * stopped: its server threads capture `this`. That is what the disabled leak-check in
     * tests.cpp is for.
     */
    bridge = std::make_shared<oatpp::mcp::utils::ApiBridge>();
    std::thread([this] { bridge->run(); }).detach();

    oatpp::mcp::capabilities::EndpointTool::Components components;
    components.schemaMapper = std::make_shared<oatpp::mcp::utils::ObjectSchemaMapper>();
    components.mappers = mappers;
    components.apiBridge = bridge;

    for(auto& endpoint : spy->getEndpoints().list) {
      bridge->addEndpoint(endpoint);
      auto tool = std::make_shared<oatpp::mcp::capabilities::EndpointTool>(endpoint, components);
      tools[str(tool->describe()->name)] = tool;
    }

    m_mapper = json;

    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // let the bridge start serving
  }

  /** Invoke a tool the way the MCP layer would: arguments as a JSON object. */
  oatpp::Object<oatpp::mcp::dto::ServerResultToolsCall>
  call(const std::string& toolName, const std::string& jsonArgs) {
    auto it = tools.find(toolName);
    if(it == tools.end()) {
      throw std::runtime_error("no such tool in the fixture: " + toolName);
    }
    oatpp::Tree args = m_mapper->readFromString<oatpp::Tree>(oatpp::String(jsonArgs));
    return it->second->call("test-session", args);
  }

};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/** Encode a string as a JSON string literal, so payloads stay readable in the source. */
static std::string jsonString(const std::string& value) {
  std::string out = "\"";
  for(char c : value) {
    switch(c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\r': out += "\\r"; break;
      case '\n': out += "\\n"; break;
      case '\t': out += "\\t"; break;
      default:   out += c;
    }
  }
  return out + "\"";
}

/**
 * A smuggled request is served by the bridge's own thread, usually a moment *after* the tool call
 * has already returned its answer. Wait before asserting that nothing arrived.
 */
static void settle(v_int32 milliseconds = 300) {
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

static bool contains(const std::vector<std::string>& values, const std::string& needle) {
  for(auto& value : values) {
    if(value == needle) {
      return true;
    }
  }
  return false;
}

static std::string describe(const std::vector<std::string>& values) {
  std::string out = "[";
  for(size_t i = 0; i < values.size(); i++) {
    if(i != 0) {
      out += ", ";
    }
    out += "'" + escape(values[i]) + "'";
  }
  return out + "]";
}

static bool failed(const oatpp::Object<oatpp::mcp::dto::ServerResultToolsCall>& result) {
  return !result || (result->isError != nullptr && *result->isError);
}

/**
 * What came back from a tool call.
 *
 * `EndpointTool::call()` throws when it refuses an argument; in the MCP layer
 * `Listener::toolsCall()` catches that and turns it into an error result. The tests call the tool
 * directly, so both shapes have to be understood here.
 */
struct Outcome {
  bool rejected = false;   ///< call() threw instead of sending the request
  bool isError = false;    ///< a result came back with isError set
  std::string detail;
};

static Outcome tryCall(Fixture& fixture, const std::string& toolName, const std::string& jsonArgs) {
  Outcome outcome;
  try {
    auto result = fixture.call(toolName, jsonArgs);
    outcome.isError = failed(result);
    outcome.detail = "isError=" + std::string(outcome.isError ? "true" : "false");
  } catch (const std::exception& e) {
    outcome.rejected = true;
    outcome.detail = e.what();
  }
  return outcome;
}

/** The request line of a second request, ending with the blank line that completes its headers. */
static const std::string kSmuggledGetUser42 = "GET /users/42 HTTP/1.1\r\nX-Second: 2\r\n\r\n";

}

void oatpp::mcp::test::ToolHttpFramingTest::onRun() {

  Checks checks("TEST[mcp::ToolHttpFraming]");

  /*
   * Deliberately leaked - `new` with no matching `delete` is the point.
   *
   * An ApiBridge cannot be destroyed. Its constructor creates an oatpp::async::Executor whose
   * destructor is `= default` while the worker threads are still joinable, so ~ApiBridge destroys a
   * joinable std::thread and the process aborts ("terminate called without an active exception").
   * Its server threads also capture `this`, so releasing it while they run would be a
   * use-after-free even if the executor allowed it. See SECURITY-FINDINGS.md, F7.
   */
  auto& fixture = *(new Fixture());

  checks.check(fixture.tools.size() == 4,
               "the fixture exposes all four spy endpoints",
               "tools = " + std::to_string(fixture.tools.size()));

  /*--- 1. control: a well-formed call reaches exactly one endpoint -------------------*/
  {
    fixture.spy->reset();

    auto outcome = tryCall(fixture, "getUsers",
      "{\"offset\":\"1\",\"limit\":\"1\",\"searchPhrase\":\"hello\"}");
    settle();

    checks.check(fixture.spy->getUsersCalls == 1, "control: the requested endpoint ran once");
    checks.check(fixture.spy->getUserByIdCalls == 0, "control: no other endpoint ran");
    checks.check(!outcome.rejected && !outcome.isError, "control: the tool call succeeded",
                 outcome.detail);
  }

  /*--- 2. request smuggling through a query parameter --------------------------------*/
  {
    fixture.spy->reset();

    /*
     * Closes the current request line and header block, then starts a new request. The first
     * request is deliberately kept well-formed - a rejected first request closes the connection
     * and hides the second one, which is an accident of the upstream parser, not a defence.
     */
    std::string injection = "x HTTP/1.1\r\nX-Injected: 1\r\n\r\n" + kSmuggledGetUser42;

    auto outcome = tryCall(fixture, "getUsers",
      "{\"offset\":\"1\",\"limit\":\"1\",\"searchPhrase\":" + jsonString(injection) + "}");
    settle();

    checks.check(!contains(fixture.spy->seenUserIds(), "42"),
                 "a query argument cannot invoke another endpoint (GET /users/42)",
                 "upstream saw userIds = " + describe(fixture.spy->seenUserIds()));
    checks.check(fixture.spy->getUsersCalls == 1,
                 "the requested endpoint still ran exactly once");
    checks.check(!outcome.rejected && !outcome.isError,
                 "the call is still answered - the injection is encoded, not dropped",
                 outcome.detail);
  }

  /*--- 3. request smuggling through a path variable ----------------------------------*/
  {
    fixture.spy->reset();

    std::string injection = "1 HTTP/1.1\r\nX-Injected: 1\r\n\r\n" + kSmuggledGetUser42;

    tryCall(fixture, "getUserById", "{\"userId\":" + jsonString(injection) + "}");
    settle();

    auto seen = fixture.spy->seenUserIds();
    checks.check(!contains(seen, "42"),
                 "a path variable cannot invoke another endpoint (GET /users/42)",
                 "upstream saw userIds = " + describe(seen));
    checks.check(seen.size() <= 1,
                 "one tool call produces at most one upstream request",
                 "upstream saw " + std::to_string(seen.size()) + " requests: " + describe(seen));
  }

  /*--- 4. header injection -----------------------------------------------------------*/
  {
    fixture.spy->reset();

    auto outcome = tryCall(fixture, "headered",
      "{\"xTest\":" + jsonString("v\r\nX-Injected: pwned") + "}");
    settle();

    checks.check(!fixture.spy->sawInjectedHeader(),
                 "a header argument cannot add a header of its own",
                 "upstream saw X-Injected: '" + escape(fixture.spy->injectedHeaderValue()) + "'");

    /*
     * Policy, not just safety: a header cannot be percent-encoded the way a URL value can, so the
     * call is refused outright rather than sent with a mangled value. If that policy ever changes,
     * this check is where it will be noticed.
     */
    checks.check(outcome.rejected, "the call is refused rather than sent with a mangled header",
                 outcome.detail);
    checks.check(fixture.spy->headeredCalls == 0, "nothing was sent to the upstream",
                 "headeredCalls = " + std::to_string(fixture.spy->headeredCalls.load()));
  }

  /*--- 5. control: a normal header value still arrives -------------------------------*/
  {
    fixture.spy->reset();

    auto outcome = tryCall(fixture, "headered", "{\"xTest\":\"bearer abc123\"}");
    settle();

    checks.check(fixture.spy->headeredCalls == 1, "control: the endpoint ran once");
    checks.check(!fixture.spy->sawInjectedHeader(), "control: no header was injected");
    checks.check(!outcome.rejected && !outcome.isError, "control: the tool call succeeded",
                 outcome.detail);
  }

  /*--- 6. control: CR/LF inside a body value stays inside the body -------------------*/
  {
    fixture.spy->reset();

    /*
     * The body is the one argument that is already safe - it goes through a mapper, and framing is
     * Content-Length based. Pinned so that a "fix" which starts escaping bodies is noticed too.
     */
    auto outcome = tryCall(fixture, "createUser",
      "{\"body\":" + jsonString(std::string("{\"a\": 1}\r\n\r\nGET /users/42 HTTP/1.1\r\n\r\n")) + "}");
    settle();

    checks.check(fixture.spy->createUserCalls == 1, "control: the body arrived as one request");
    checks.check(!contains(fixture.spy->seenUserIds(), "42"),
                 "a body value cannot invoke another endpoint",
                 "upstream saw userIds = " + describe(fixture.spy->seenUserIds()));
    checks.check(!outcome.rejected && !outcome.isError, "control: the tool call succeeded",
                 outcome.detail);
  }

  checks.assertNoFailures();
}
