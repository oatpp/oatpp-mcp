//
// Shared plumbing for the tests that drive the SSE endpoints over a real socket.
//
// Extracted from SseAccessTest. The reason is not tidiness: SseBackpressureTest needs the same
// server and the same request helper, and a second copy of "how do we talk to our own server" is
// how two tests end up disagreeing about what the transport does.
//

#ifndef oatpp_mcp_test_SseTestSupport_hpp
#define oatpp_mcp_test_SseTestSupport_hpp

#include "TestChecks.hpp"

#include "oatpp-mcp/event/Server.hpp"
#include "oatpp-mcp/sse/Controller.hpp"
#include "oatpp-mcp/utils/AccessGuard.hpp"

#include "oatpp/json/ObjectMapper.hpp"
#include "oatpp/web/client/HttpRequestExecutor.hpp"
#include "oatpp/web/mime/ContentMappers.hpp"
#include "oatpp/web/protocol/http/outgoing/BufferBody.hpp"
#include "oatpp/web/server/HttpConnectionHandler.hpp"
#include "oatpp/web/server/HttpRouter.hpp"
#include "oatpp/network/Server.hpp"
#include "oatpp/network/tcp/client/ConnectionProvider.hpp"
#include "oatpp/network/tcp/server/ConnectionProvider.hpp"

#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace oatpp { namespace mcp { namespace test {

using Response = oatpp::web::protocol::http::incoming::Response;
using HeaderList = std::vector<std::pair<std::string, std::string>>;

/**
 * Records what a session was handed, and can be stopped from taking anything.
 *
 * Not the real <code>Listener</code>, and not a read of the session's own in-stream: a session that
 * is registered is being listened to by its own thread, which consumes the stream before a test can.
 * Delivery is therefore asserted on the listener, which is where it matters anyway - and which is
 * the only way to assert that something did <i>not</i> arrive.
 *
 * <b>Why it can be gated.</b> "The queue is full" is not a state a test can reach by asking nicely:
 * a listener that keeps up never lets the queue fill. Closing the gate makes the session stop
 * reading, which is the whole of finding F8, and opening it again is how a test shows that the
 * refusal was about the queue and not about the endpoint being broken.
 */
class GatedListener : public oatpp::mcp::event::Session::EventListener {
private:
  std::mutex m_mutex;
  std::condition_variable m_cv;
  bool m_gated;
  v_int32 m_entered;
  std::vector<std::string> m_seen;
public:

  GatedListener()
    : m_gated(false)
    , m_entered(0)
  {}

  /**
   * A gated listener does not return from this method - which is what parks the session thread and
   * backs the queue up. The message is recorded first, so that "delivered" and "acknowledged" stay
   * separate facts even when the session never gets as far as processing it.
   */
  void onEvent(oatpp::mcp::event::Session&, const oatpp::mcp::event::Event& event) override {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_seen.push_back(oatpp::mcp::test::str(event.data));
    m_entered ++;
    m_cv.notify_all();
    while(m_gated) {
      m_cv.wait(lock);
    }
  }

  /** Stop (or start) taking messages. */
  void gate(bool on) {
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      m_gated = on;
    }
    m_cv.notify_all();
  }

  /** How many messages this listener has actually been given. */
  v_int32 count() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_entered;
  }

  std::vector<std::string> seen() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_seen;
  }

  std::string last() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_seen.empty() ? std::string() : m_seen.back();
  }

  /** Wait until at least <code>count</code> messages have been taken out of the session. */
  bool waitTaken(v_int32 count, v_int32 timeoutMillis) {
    return waitFor([&] { return this->count() >= count; }, timeoutMillis);
  }

};

/**
 * One HTTP request, and the response that came back with it.
 *
 * The response object is what holds the connection open: an SSE response never completes, so a test
 * that wants its session to stay alive has to keep the returned pointer alive, and a test that wants
 * it to die has to let go of it.
 */
static inline std::shared_ptr<Response> send(v_uint16 port,
                                             const char* method,
                                             const char* path,
                                             const HeaderList& headers = HeaderList(),
                                             const std::string& body = std::string())
{
  auto provider = std::make_shared<oatpp::network::tcp::client::ConnectionProvider>(
    oatpp::network::Address("127.0.0.1", port, oatpp::network::Address::IP_4));
  oatpp::web::client::HttpRequestExecutor executor(provider);

  oatpp::web::protocol::http::Headers h;
  for(const auto& header : headers) {
    h.put(oatpp::String(header.first), oatpp::String(header.second));
  }

  std::shared_ptr<oatpp::web::protocol::http::outgoing::Body> outBody;
  if(!body.empty()) {
    outBody = std::make_shared<oatpp::web::protocol::http::outgoing::BufferBody>(
      oatpp::String(body), "application/json");
  }

  return executor.execute(oatpp::String(method), oatpp::String(path), h, outBody, nullptr);
}

/**
 * An MCP-over-SSE server on 127.0.0.1, configured per test.
 *
 * A real socket rather than a unit-level call into the controller, because the findings are about
 * what an unauthenticated remote client can do - and because "the endpoint never asked" is invisible
 * to a test that does not send a request.
 */
class SseFixture {
public:
  std::shared_ptr<oatpp::mcp::event::Server> eventServer;
  std::shared_ptr<GatedListener> recorder;
  v_uint16 port = 0;
private:
  std::shared_ptr<oatpp::network::Server> server;
  std::thread thread;
public:

  SseFixture(const oatpp::mcp::utils::AccessGuard::Config& access,
             const oatpp::mcp::event::Server::Config& sessions = oatpp::mcp::event::Server::Config())
  {
    recorder = std::make_shared<GatedListener>();
    eventServer = std::make_shared<oatpp::mcp::event::Server>(nullptr, sessions);

    auto json = std::make_shared<oatpp::json::ObjectMapper>();
    auto mappers = std::make_shared<oatpp::web::mime::ContentMappers>();
    mappers->putMapper(json);

    auto controller = std::make_shared<oatpp::mcp::sse::Controller>(
      eventServer, recorder, mappers, "mcp/", access);

    auto router = oatpp::web::server::HttpRouter::createShared();
    router->addController(controller);

    std::shared_ptr<oatpp::network::tcp::server::ConnectionProvider> provider;
    std::string failures;
    for(v_uint16 candidate = 3131; candidate < 3191 && provider == nullptr; candidate++) {
      try {
        provider = oatpp::network::tcp::server::ConnectionProvider::createShared(
          {"127.0.0.1", candidate, oatpp::network::Address::IP_4});
        port = candidate;
      } catch (const std::exception& e) {
        failures += e.what();
        failures += "; ";
      }
    }
    if(provider == nullptr) {
      throw std::runtime_error("could not bind a port for the test server: " + failures);
    }

    auto handler = oatpp::web::server::HttpConnectionHandler::createShared(router);
    server = std::make_shared<oatpp::network::Server>(provider, handler);
    thread = std::thread([this] { server->run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(150)); // let it start accepting
  }

  ~SseFixture() {
    /*
     * Ungate first: a session thread parked inside a gated listener cannot notice that its session
     * was closed, and this destructor would wait for it.
     */
    recorder->gate(false);
    /*
     * Every SSE connection holds a session thread and a connection thread, both parked - the writer
     * on the outbound stream, the session on the inbound one. Closing the sessions is what releases
     * the writer; without it this destructor waits for threads that are waiting for a client that has
     * already gone. (That is finding F5, and it is why it is worth fixing.)
     *
     * Waiting for the registry to empty afterwards is what makes the object-leak check meaningful:
     * a session still running holds its queues, and its queues hold messages.
     */
    eventServer->closeSessions();
    waitUntilEmpty(3000);
    server->stop();
    if(thread.joinable()) {
      thread.join();
    }
  }

  /** Wait until the registry is empty, or give up. */
  bool waitUntilEmpty(v_int32 timeoutMillis) {
    return waitFor([&] { return eventServer->sessionCount() == 0; }, timeoutMillis);
  }

};

/** A server that only accepts the address it is bound to - the recommended local configuration. */
static inline oatpp::mcp::utils::AccessGuard::Config localOnly() {
  oatpp::mcp::utils::AccessGuard::Config config;
  config.allowedHosts.push_back("127.0.0.1");
  return config;
}

}}}

#endif // oatpp_mcp_test_SseTestSupport_hpp
