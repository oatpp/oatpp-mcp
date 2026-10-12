#include "EventStreamTest.hpp"

#include "LogCapture.hpp"
#include "TestChecks.hpp"

#include "oatpp-mcp/event/EventStream.hpp"

#include <chrono>
#include <string>
#include <thread>
#include <vector>

using oatpp::mcp::event::Event;
using oatpp::mcp::event::EventStream;
using oatpp::mcp::event::PostResult;
using oatpp::mcp::event::StreamStats;

using oatpp::mcp::test::CapturingLogger;
using oatpp::mcp::test::Checks;
using oatpp::mcp::test::ScopedLogger;
using oatpp::mcp::test::isSingleLine;
using oatpp::mcp::test::str;
using oatpp::mcp::test::withTag;
using oatpp::mcp::test::withText;

namespace {

/** Where a drop is reported. Must match the tag in `EventStream::post()`. */
const char* const kDropTag = "[oatpp::mcp::event::EventStream::post()]";

/** An event name this test can recognise in a captured log record. */
const char* const kOverflow = "f8-overflow";

constexpr std::chrono::milliseconds kReadTimeout{50};

Event anEvent(const std::string& name, const std::string& data) {
  Event event;
  event.name = oatpp::String(name);
  event.data = oatpp::String(data);
  return event;
}

std::string reason(PostResult result) {
  return oatpp::mcp::event::describe(result);
}

/** Records about this test's own events - other tests' threads may still be logging. */
std::vector<oatpp::mcp::test::Record> about(const std::vector<oatpp::mcp::test::Record>& records) {
  return withText(withTag(records, kDropTag), kOverflow);
}

std::string listing(const std::vector<oatpp::mcp::test::Record>& records) {
  std::string out;
  for(auto& r : records) {
    out += "\n  '" + oatpp::mcp::test::escape(r.message) + "'";
  }
  return out;
}

}

void oatpp::mcp::test::EventStreamTest::onRun() {

  Checks checks("TEST[mcp::EventStream]");

  /*--- control: what goes in comes out, in order --------------------------------------*/
  {
    EventStream stream;

    checks.check(stream.maxQueueSize() == EventStream::DefaultMaxQueueSize,
                 "the default queue is the documented one",
                 "maxQueueSize=" + std::to_string(stream.maxQueueSize()));
    checks.check(stream.isOpen(), "a new stream is open");

    checks.check(isQueued(stream.post(anEvent("e", "first"))),
                 "an event that fits is queued");
    checks.check(isQueued(stream.post(anEvent("e", "second"))),
                 "so is the next one");

    auto first = stream.read(kReadTimeout);
    auto second = stream.read(kReadTimeout);
    checks.check((bool) first && str(first.data) == "first",
                 "events come back in the order they went in",
                 "got '" + str(first.data) + "'");
    checks.check((bool) second && str(second.data) == "second",
                 "and not in any other order",
                 "got '" + str(second.data) + "'");

    auto stats = stream.stats();
    checks.check(stats.queued == 2 && stats.dropped() == 0,
                 "two queued, nothing dropped",
                 "queued=" + std::to_string(stats.queued)
                   + ", dropped=" + std::to_string(stats.dropped()));
  }

  /*--- the bound: a full queue refuses, and says so -----------------------------------*/
  {
    EventStream stream(2);

    checks.check(isQueued(stream.post(anEvent("e", "a"))), "bound: the first fits");
    checks.check(isQueued(stream.post(anEvent("e", "b"))), "bound: the second fills it");

    auto third = stream.post(anEvent("e", "c"));
    checks.check(third == PostResult::DroppedFull,
                 "bound: the third is refused, and refused as full",
                 "post() said '" + reason(third) + "'");

    /*
     * Refusing has to mean "this one, and only this one": displacing the oldest queued event would
     * silently drop the message that has been waiting longest, which is the one the client has
     * already given up on hearing about.
     */
    auto first = stream.read(kReadTimeout);
    auto second = stream.read(kReadTimeout);
    checks.check((bool) first && str(first.data) == "a",
                 "bound: refusing does not displace what is already queued",
                 "got '" + str(first.data) + "'");
    checks.check((bool) second && str(second.data) == "b",
                 "bound: nor the second",
                 "got '" + str(second.data) + "'");

    auto after = stream.read(kReadTimeout);
    checks.check(!after,
                 "bound: the refused event never arrives later either",
                 "got '" + str(after.data) + "'");

    auto stats = stream.stats();
    checks.check(stats.queued == 2 && stats.droppedFull == 1 && stats.droppedClosed == 0,
                 "bound: the counters say exactly what happened",
                 "queued=" + std::to_string(stats.queued)
                   + ", full=" + std::to_string(stats.droppedFull)
                   + ", closed=" + std::to_string(stats.droppedClosed));
  }

  /*--- a closed stream refuses, and says why ------------------------------------------*/
  {
    EventStream stream(4);
    stream.close();

    checks.check(!stream.isOpen(), "close() closes the stream");

    auto outcome = stream.post(anEvent("e", "into a closed stream"));
    checks.check(outcome == PostResult::DroppedClosed,
                 "a closed stream refuses, and refuses as closed",
                 "post() said '" + reason(outcome) + "'");
    checks.check(!isQueued(outcome), "and isQueued() agrees - which is what callers test");
    checks.check(stream.stats().droppedClosed == 1 && stream.stats().droppedFull == 0,
                 "the two reasons are counted separately",
                 "closed=" + std::to_string(stream.stats().droppedClosed)
                   + ", full=" + std::to_string(stream.stats().droppedFull));
  }

  /*--- closing stops the waiting, not the reading -------------------------------------*/
  {
    EventStream stream(4);
    stream.post(anEvent("e", "1"));
    stream.post(anEvent("e", "2"));
    stream.close();

    auto first = stream.read(kReadTimeout);
    auto second = stream.read(kReadTimeout);
    checks.check((bool) first && str(first.data) == "1",
                 "close does not discard what is already queued",
                 "got '" + str(first.data) + "'");
    checks.check((bool) second && str(second.data) == "2",
                 "both queued answers survive the teardown",
                 "got '" + str(second.data) + "'");

    auto third = stream.read(kReadTimeout);
    checks.check(!third,
                 "once it is drained, the reader is told there is nothing more",
                 "got '" + str(third.data) + "'");
    checks.check(!stream.read(std::chrono::milliseconds(0)),
                 "and a reader that waits forever is not kept waiting by a closed stream");
  }

  /*--- refusing is a refusal, not a wait ----------------------------------------------*/
  {
    auto capture = std::make_shared<CapturingLogger>();
    v_int32 refused = 0;
    v_int64 elapsedMillis = 0;

    {
      ScopedLogger scope(capture);   // 1000 refusals would otherwise print 10 lines of their own

      EventStream stream(1);
      stream.post(anEvent(kOverflow, "fills the queue"));

      auto start = std::chrono::steady_clock::now();
      for(v_int32 i = 0; i < 1000; i++) {
        if(stream.post(anEvent(kOverflow, "over the limit")) == PostResult::DroppedFull) {
          refused ++;
        }
      }
      elapsedMillis = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    }

    checks.check(refused == 1000,
                 "a producer that outruns its reader is refused every time",
                 "refused " + std::to_string(refused) + " of 1000");
    /*
     * The property, not the constant: `post()` runs on a session thread and on an HTTP connection
     * thread. Making it wait for a reader that may have died is how a lost message becomes a hung
     * server, so it refuses instead - and refusing has to be immediate.
     */
    checks.check(elapsedMillis < 500,
                 "refusing is immediate - post() never waits for a reader",
                 "1000 refusals took " + std::to_string(elapsedMillis) + "ms");

    auto mine = about(capture->records());
    checks.check(!mine.empty(),
                 "a drop is reported to the operator's log, not only to the caller",
                 "captured " + std::to_string(mine.size()) + " records" + listing(mine));
    checks.check(mine.size() <= 20,
                 "and it is reported once, not once per dropped message",
                 "1000 drops produced " + std::to_string(mine.size()) + " records" + listing(mine));
    checks.check(!withText(mine, "queue full").empty(),
                 "the record says why",
                 "captured:" + listing(mine));
    checks.check(!withText(mine, "dropped=1000").empty(),
                 "and how much has been lost, so that a sampled line still reports the total",
                 "captured:" + listing(mine));

    bool allSingleLine = true;
    for(auto& r : mine) {
      allSingleLine = allSingleLine && isSingleLine(r.message);
    }
    checks.check(allSingleLine, "a drop record is one line", "captured:" + listing(mine));
  }

  /*--- the two reasons are distinguishable in the log too -----------------------------*/
  {
    auto capture = std::make_shared<CapturingLogger>();
    {
      ScopedLogger scope(capture);
      EventStream stream(4);
      stream.close();
      stream.post(anEvent(kOverflow, "after close"));
    }
    auto mine = about(capture->records());
    checks.check(!withText(mine, "stream closed").empty(),
                 "a drop into a closed stream says so, rather than blaming the queue",
                 "captured:" + listing(mine));
  }

  /*--- unbounded is a thing a caller can ask for, and means what it says --------------*/
  {
    EventStream stream(0);
    v_int32 queued = 0;
    for(v_int32 i = 0; i < 1000; i++) {
      if(isQueued(stream.post(anEvent("e", std::to_string(i))))) {
        queued ++;
      }
    }
    checks.check(queued == 1000,
                 "a queue with no limit accepts everything it is given",
                 "queued " + std::to_string(queued));
    checks.check(stream.stats().dropped() == 0, "and drops nothing");
  }

  /*--- two threads: nothing accepted is lost, nothing is invented ---------------------*/
  {
    const v_int32 total = 5000;
    auto stream = std::make_shared<EventStream>(8);

    std::thread producer([stream, total]{
      for(v_int32 i = 0; i < total; i++) {
        stream->post(anEvent("seq", std::to_string(i)));
      }
      stream->close();     // closing is what ends the consumer's read(0)
    });

    std::vector<v_int64> delivered;
    delivered.reserve(total);
    for(;;) {
      auto event = stream->read(std::chrono::milliseconds(0));
      if(!event) {
        break;
      }
      delivered.push_back(std::stoll(*event.data));
    }
    producer.join();

    auto stats = stream->stats();

    checks.check(stats.queued + stats.dropped() == (v_uint64) total,
                 "every event posted was either queued or refused - none vanished",
                 "posted=" + std::to_string(total) + ", queued=" + std::to_string(stats.queued)
                   + ", dropped=" + std::to_string(stats.dropped()));
    checks.check((v_uint64) delivered.size() == stats.queued,
                 "and everything that was queued was delivered - a close drains, it does not discard",
                 "delivered=" + std::to_string(delivered.size())
                   + ", queued=" + std::to_string(stats.queued));
    checks.check(!delivered.empty() && delivered.front() == 0,
                 "the first event is always the first delivered",
                 delivered.empty() ? "delivered nothing"
                                   : "first=" + std::to_string(delivered.front()));

    bool increasing = true;
    for(size_t i = 1; i < delivered.size(); i++) {
      if(delivered[i] <= delivered[i - 1]) {
        increasing = false;
        break;
      }
    }
    checks.check(increasing,
                 "a refused event does not reorder the ones that were accepted");
  }

  checks.assertNoFailures();
}
