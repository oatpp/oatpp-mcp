//
// The bounded queue between a session and whoever serves it: what it accepts, what it refuses, and
// what it says when it refuses.
//
// See SECURITY-FINDINGS.md, finding F8: `EventStream::post()` used to return `void` and to discard
// an event once the queue was full or the stream closed. Nothing above it could tell a delivered
// message from a lost one - including the HTTP endpoint that answered 200 "OK" to a message it had
// already thrown away.
//

#ifndef oatpp_mcp_test_EventStreamTest_hpp
#define oatpp_mcp_test_EventStreamTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * {@link oatpp::mcp::event::EventStream}: bounded queueing, reported drops, and counters.
 */
class EventStreamTest : public oatpp::test::UnitTest {
public:

  EventStreamTest()
    : oatpp::test::UnitTest("TEST[mcp::EventStream]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_EventStreamTest_hpp
