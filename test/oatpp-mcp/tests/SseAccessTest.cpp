#include "SseAccessTest.hpp"

#include "SseTestSupport.hpp"
#include "TestChecks.hpp"

using oatpp::mcp::test::Checks;
using oatpp::mcp::test::localOnly;
using oatpp::mcp::test::send;
using oatpp::mcp::test::str;
using oatpp::mcp::test::waitFor;

/*
 * The server, the socket and the recording listener are shared with SseBackpressureTest - see
 * SseTestSupport.hpp. The name stays: every case below reads as "a fixture, a request, an answer".
 */
using Fixture = oatpp::mcp::test::SseFixture;

namespace {

using oatpp::mcp::test::HeaderList;

}

void oatpp::mcp::test::SseAccessTest::onRun() {

  Checks checks("TEST[mcp::SseAccess]");

  /*--- control: a native client opens a session ----------------------------------------*/
  {
    Fixture fixture(localOnly());

    auto response = send(fixture.port, "GET", "/mcp/sse");
    checks.check(response != nullptr, "GET /mcp/sse is answered");
    checks.check(response && response->getStatusCode() == 200,
                 "control: a client that sends no Origin opens a session",
                 "status=" + std::to_string(response ? response->getStatusCode() : 0));
    checks.check(fixture.eventServer->sessionCount() == 1,
                 "control: exactly one session was created",
                 "sessions=" + std::to_string(fixture.eventServer->sessionCount()));
  }

  /*--- Origin --------------------------------------------------------------------------*/
  {
    Fixture fixture(localOnly());

    auto crossOrigin = send(fixture.port, "GET", "/mcp/sse",
                            {{"Origin", "http://evil.example"}});
    checks.check(crossOrigin && crossOrigin->getStatusCode() == 403,
                 "a cross-origin GET /sse is refused with 403",
                 "status=" + std::to_string(crossOrigin ? crossOrigin->getStatusCode() : 0));
    checks.check(fixture.eventServer->sessionCount() == 0,
                 "a refused GET /sse opens no session",
                 "sessions=" + std::to_string(fixture.eventServer->sessionCount()));

    /*
     * The order matters: a POST that is refused must not have been delivered first, which is what
     * checking the in-stream after the refusal tests.
     */
    auto session = fixture.eventServer->startNewSession(fixture.recorder);
    checks.check(session != nullptr, "a session could be opened for the POST control");

    auto path = std::string("/mcp/sessions/") + str(session->getId());
    auto refused = send(fixture.port, "POST", path.c_str(),
                        {{"Origin", "http://evil.example"}}, "{\"jsonrpc\":\"2.0\"}");
    checks.check(refused && refused->getStatusCode() == 403,
                 "a cross-origin POST to a live session is refused with 403",
                 "status=" + std::to_string(refused ? refused->getStatusCode() : 0));

    /*
     * Given a moment to be delivered if it were going to be: the check is that nothing arrived, and
     * "not yet" looks exactly like that without a wait.
     */
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    checks.check(fixture.recorder->count() == 0, "a refused POST delivers nothing to the session",
                 "delivered: '" + fixture.recorder->last() + "'");

    session->close();
  }

  /*--- Host: DNS rebinding -------------------------------------------------------------*/
  {
    Fixture fixture(localOnly());

    /*
     * The attacker's domain resolved to 127.0.0.1, so the browser sends its own name in Host and an
     * Origin that agrees with it. The pair is self-consistent; only the allow-list notices.
     */
    auto rebound = send(fixture.port, "GET", "/mcp/sse",
                        {{"Host", "rebound.attacker.example"},
                         {"Origin", "http://rebound.attacker.example"}});
    checks.check(rebound && rebound->getStatusCode() == 403,
                 "a Host the server is not configured for is refused with 403",
                 "status=" + std::to_string(rebound ? rebound->getStatusCode() : 0));
    checks.check(fixture.eventServer->sessionCount() == 0,
                 "a refused Host opens no session");
  }

  /*--- an unknown session is a 404 -----------------------------------------------------*/
  {
    Fixture fixture(localOnly());

    auto missing = send(fixture.port, "POST", "/mcp/sessions/0f6f0b4a-3f0a-4a1a-9d1c-000000000000",
                        HeaderList(), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
    checks.check(missing && missing->getStatusCode() == 404,
                 "POST to an unknown session answers 404, not 200",
                 "status=" + std::to_string(missing ? missing->getStatusCode() : 0));

    /* The control: the same POST to a session that exists is accepted and delivered. */
    auto session = fixture.eventServer->startNewSession(fixture.recorder);
    auto path = std::string("/mcp/sessions/") + str(session->getId());
    auto ok = send(fixture.port, "POST", path.c_str(), HeaderList(), "{\"jsonrpc\":\"2.0\"}");
    checks.check(ok && ok->getStatusCode() == 200,
                 "POST to a live session is still accepted",
                 "status=" + std::to_string(ok ? ok->getStatusCode() : 0));

    checks.check(waitFor([&] { return fixture.recorder->count() == 1; }, 1000),
                 "the delivered message reaches the session's listener",
                 "count=" + std::to_string(fixture.recorder->count())
                   + ", last='" + fixture.recorder->last() + "'");
    checks.check(fixture.recorder->last() == "{\"jsonrpc\":\"2.0\"}",
                 "and it is the message that was posted, unchanged",
                 "last='" + fixture.recorder->last() + "'");

    session->close();
  }

  /*--- the session cap -----------------------------------------------------------------*/
  {
    oatpp::mcp::event::Server::Config sessions;
    sessions.maxSessions = 1;
    Fixture fixture(localOnly(), sessions);

    auto first = send(fixture.port, "GET", "/mcp/sse");
    checks.check(first && first->getStatusCode() == 200,
                 "cap: the first session is accepted",
                 "status=" + std::to_string(first ? first->getStatusCode() : 0));

    auto second = send(fixture.port, "GET", "/mcp/sse");
    checks.check(second && second->getStatusCode() == 503,
                 "cap: a server at its limit answers 503 rather than opening another session",
                 "status=" + std::to_string(second ? second->getStatusCode() : 0));
    checks.check(fixture.eventServer->sessionCount() == 1,
                 "cap: the refused request created nothing",
                 "sessions=" + std::to_string(fixture.eventServer->sessionCount()));

    /*
     * A 503 that never clears is a different bug, so the limit has to be shown to be about the live
     * sessions and not about the number of requests made.
     */
    fixture.eventServer->closeSessions();
    checks.check(fixture.waitUntilEmpty(3000), "cap: closing the sessions empties the registry");

    auto third = send(fixture.port, "GET", "/mcp/sse");
    checks.check(third && third->getStatusCode() == 200,
                 "cap: a freed slot is usable again",
                 "status=" + std::to_string(third ? third->getStatusCode() : 0));
  }

  /*--- the idle timeout ----------------------------------------------------------------*/
  {
    oatpp::mcp::event::Server::Config sessions;
    sessions.sessionIdleTimeoutMillis = 250;
    Fixture fixture(localOnly(), sessions);

    auto response = send(fixture.port, "GET", "/mcp/sse");
    checks.check(response && response->getStatusCode() == 200,
                 "ttl: a session is opened as usual");
    checks.check(fixture.eventServer->sessionCount() == 1, "ttl: the session is registered");

    /*
     * The client stays connected and silent - which is the case the timeout exists for. Nothing
     * else reclaims a session whose client has stopped talking but has not hung up.
     */
    checks.check(waitFor([&] { return fixture.eventServer->sessionCount() == 0; }, 3000),
                 "ttl: a silent session is closed by the idle timeout",
                 "sessions=" + std::to_string(fixture.eventServer->sessionCount()));
  }

  /*--- the default configuration is not a denial of service to honest clients -----------*/
  {
    oatpp::mcp::event::Server::Config sessions;
    sessions.sessionIdleTimeoutMillis = 0;   // the default: never expire
    Fixture fixture(oatpp::mcp::utils::AccessGuard::Config(), sessions);

    auto response = send(fixture.port, "GET", "/mcp/sse");
    checks.check(response && response->getStatusCode() == 200,
                 "default: any Host is accepted when no allow-list is configured",
                 "status=" + std::to_string(response ? response->getStatusCode() : 0));

    bool expired = waitFor([&] { return fixture.eventServer->sessionCount() == 0; }, 1200);
    checks.check(!expired,
                 "default: a session with no idle timeout is not expired out from under its client");
  }

  checks.assertNoFailures();
}
