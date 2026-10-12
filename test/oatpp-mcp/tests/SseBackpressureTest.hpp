//
// What the SSE endpoints answer when a session cannot take the message.
//
// See SECURITY-FINDINGS.md, finding F8: `POST /mcp/sessions/{id}` answered 200 "OK" whatever
// happened to the message, because `EventStream::post()` had no way to say it had discarded it. A
// client that was told "OK" and got no reply had no way to tell a busy server from a broken one, and
// neither did anybody watching the server.
//

#ifndef oatpp_mcp_test_SseBackpressureTest_hpp
#define oatpp_mcp_test_SseBackpressureTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * {@link oatpp::mcp::sse::Controller}'s answers when the session queue is full or closed.
 */
class SseBackpressureTest : public oatpp::test::UnitTest {
public:

  SseBackpressureTest()
    : oatpp::test::UnitTest("TEST[mcp::SseBackpressure]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_SseBackpressureTest_hpp
