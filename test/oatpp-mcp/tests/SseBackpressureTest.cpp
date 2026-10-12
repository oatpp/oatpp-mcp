#include "SseBackpressureTest.hpp"

#include "SseTestSupport.hpp"
#include "TestChecks.hpp"

#include <string>
#include <thread>
#include <vector>

using oatpp::mcp::test::Checks;
using oatpp::mcp::test::HeaderList;
using oatpp::mcp::test::SseFixture;
using oatpp::mcp::test::localOnly;
using oatpp::mcp::test::send;
using oatpp::mcp::test::str;
using oatpp::mcp::test::waitFor;

namespace {

/** A JSON-RPC call, tagged so that delivery of one message can be told from delivery of another. */
std::string message(const std::string& tag) {
  return std::string("{\"jsonrpc\":\"2.0\",\"id\":\"") + tag + "\",\"method\":\"tools/list\"}";
}

std::string sessionPath(const std::shared_ptr<oatpp::mcp::event::Session>& session) {
  return std::string("/mcp/sessions/") + str(session->getId());
}

struct Answer {
  v_int32 status = 0;
  std::string body;
  std::string retryAfter;
};

Answer postTo(const SseFixture& fixture,
              const std::shared_ptr<oatpp::mcp::event::Session>& session,
              const std::string& tag)
{
  Answer answer;
  try {
    auto response = send(fixture.port, "POST", sessionPath(session).c_str(),
                         HeaderList(), message(tag));
    if(response) {
      answer.status = response->getStatusCode();
      answer.body = str(response->readBodyToString());
      auto header = response->getHeader("Retry-After");
      answer.retryAfter = header != nullptr ? std::string(*header) : std::string();
    }
  } catch (const std::exception& e) {
    answer.body = std::string("the request itself failed: ") + e.what();
  }
  return answer;
}

std::string describe(const std::vector<std::string>& seen) {
  std::string out;
  for(auto& s : seen) {
    out += "'" + s + "' ";
  }
  return out;
}

std::string describe(const Answer& answer) {
  return "status=" + std::to_string(answer.status) + ", body='" + answer.body
       + "', Retry-After='" + answer.retryAfter + "'";
}

}

void oatpp::mcp::test::SseBackpressureTest::onRun() {

  Checks checks("TEST[mcp::SseBackpressure]");

  /*--- control: a session that is reading is accepted ----------------------------------*/
  {
    SseFixture fixture(localOnly());

    auto session = fixture.eventServer->startNewSession(fixture.recorder);
    checks.check(session != nullptr, "control: a session could be opened");

    auto answer = postTo(fixture, session, "1");
    checks.check(answer.status == 200,
                 "control: a message for a session that is reading is accepted",
                 describe(answer));
    checks.check(waitFor([&] { return fixture.recorder->count() == 1; }, 2000),
                 "control: and it is delivered",
                 "count=" + std::to_string(fixture.recorder->count()));

    session->close();
  }

  /*--- a session that stopped reading is refused, not accepted ------------------------*/
  {
    oatpp::mcp::event::Server::Config config;
    config.maxQueuedEvents = 1;
    SseFixture fixture(localOnly(), config);

    auto session = fixture.eventServer->startNewSession(fixture.recorder);
    fixture.recorder->gate(true);       // the client has stopped reading

    auto taken = postTo(fixture, session, "1");
    checks.check(taken.status == 200, "queue: the message the session takes is accepted",
                 describe(taken));
    checks.check(fixture.recorder->waitTaken(1, 2000),
                 "queue: the session is holding that message and taking nothing else");

    auto queued = postTo(fixture, session, "2");
    checks.check(queued.status == 200, "queue: the next one fits (the limit is 1)",
                 describe(queued));

    auto over = postTo(fixture, session, "3");
    checks.check(over.status == 503,
                 "queue: a message for a full queue is refused with 503 - not accepted with 200",
                 describe(over));
    checks.check(over.body != "OK",
                 "and the answer does not claim to have taken it",
                 describe(over));
    checks.check(!over.retryAfter.empty(),
                 "with a Retry-After, because 'later' is the truth and 'never' is not",
                 describe(over));

    auto again = postTo(fixture, session, "4");
    checks.check(again.status == 503, "queue: it stays refused while the queue stays full",
                 describe(again));

    /*
     * The other half of the promise. A 503 means "not taken", so a refused message must not arrive
     * - a refusal that delivered anyway is a different bug wearing this one's clothes, and only a
     * test can tell them apart.
     */
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto seen = fixture.recorder->seen();
    checks.check(seen.size() == 1 && seen[0].find("\"1\"") != std::string::npos,
                 "the refused messages were not delivered",
                 "the session saw: " + describe(seen));

    /* The limit is about the queue, not about the endpoint having given up on everything. */
    fixture.recorder->gate(false);
    checks.check(fixture.recorder->waitTaken(2, 2000),
                 "queue: the queued message is delivered once the client starts reading again",
                 "the session saw: " + describe(fixture.recorder->seen()));

    auto after = postTo(fixture, session, "5");
    checks.check(after.status == 200, "queue: a freed queue accepts again", describe(after));
    checks.check(fixture.recorder->waitTaken(3, 2000),
                 "queue: and that message arrives too",
                 "the session saw: " + describe(fixture.recorder->seen()));

    session->close();
  }

  /*--- a session that has gone away is not accepted either ----------------------------*/
  {
    SseFixture fixture(localOnly());

    auto session = fixture.eventServer->startNewSession(fixture.recorder);

    /*
     * The gate is what makes this a test of the closed session rather than of the registry. A session
     * unregisters itself as its thread finishes, so closing one and then posting to it would usually
     * find no session at all - and "unknown session" is a different branch that happens to answer 404
     * as well. Holding the session thread inside the listener keeps a *closed but still registered*
     * session in the registry, which is the state the transport has to answer honestly.
     */
    fixture.recorder->gate(true);
    postTo(fixture, session, "held");
    checks.check(fixture.recorder->waitTaken(1, 2000),
                 "closed: the session thread is inside the listener and cannot leave");

    session->close();
    checks.check(fixture.eventServer->getSession(session->getId()) != nullptr,
                 "closed: and the session is still registered - the interesting state");

    auto answer = postTo(fixture, session, "late");
    checks.check(answer.status == 404,
                 "a message for a closed session is refused with 404, not accepted with 200",
                 describe(answer));
    checks.check(answer.body != "OK", "and is not reported as taken", describe(answer));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    checks.check(fixture.recorder->count() == 1,
                 "and the message posted after the close is not delivered",
                 "the session saw: " + describe(fixture.recorder->seen()));

    fixture.recorder->gate(false);
  }

  /*--- one stalled client does not spend another client's capacity --------------------*/
  {
    oatpp::mcp::event::Server::Config config;
    config.maxQueuedEvents = 1;
    SseFixture fixture(localOnly(), config);

    auto stalled = fixture.eventServer->startNewSession(fixture.recorder);
    auto other = fixture.eventServer->startNewSession(fixture.recorder);
    fixture.recorder->gate(true);

    postTo(fixture, stalled, "s1");
    checks.check(fixture.recorder->waitTaken(1, 2000),
                 "shared: the stalled session is holding a message");
    postTo(fixture, stalled, "s2");

    auto over = postTo(fixture, stalled, "s3");
    checks.check(over.status == 503, "shared: that session is over its limit", describe(over));

    auto healthy = postTo(fixture, other, "h1");
    checks.check(healthy.status == 200,
                 "shared: a different session is still usable - the bound is per session, "
                 "so one client that stopped reading cannot shut the others out",
                 describe(healthy));

    fixture.recorder->gate(false);
    stalled->close();
    other->close();
  }

  /*--- the default is not a denial of service to a client that pipelines --------------*/
  {
    SseFixture fixture(localOnly());     // default queue: EventStream::DefaultMaxQueueSize

    auto session = fixture.eventServer->startNewSession(fixture.recorder);
    v_int32 accepted = 0;
    for(v_int32 i = 0; i < 50; i++) {
      if(postTo(fixture, session, std::to_string(i)).status == 200) {
        accepted ++;
      }
    }
    checks.check(accepted == 50,
                 "default: fifty pipelined messages to a session with the default queue are all "
                 "accepted - the bound is there to bound memory, not to throttle working clients",
                 "accepted " + std::to_string(accepted) + " of 50");
    session->close();
  }

  checks.assertNoFailures();
}
