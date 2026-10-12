//
// The SSE endpoints over a real socket: who gets in, who gets refused, and what a refusal costs.
//
// See SECURITY-FINDINGS.md, finding F4. The policy itself is unit-tested by AccessGuardTest; this
// test is about the wiring, because every part of it is individually easy to get wrong in a way the
// unit test cannot see: an endpoint that forgets to consult the guard, a session opened before the
// request is checked, an unknown session answered 200, a full server dereferencing the session it
// was not given.
//

#ifndef oatpp_mcp_test_SseAccessTest_hpp
#define oatpp_mcp_test_SseAccessTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * Access control and session limits on the HTTP endpoints.
 */
class SseAccessTest : public oatpp::test::UnitTest {
public:

  SseAccessTest()
    : oatpp::test::UnitTest("TEST[mcp::SseAccess]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_SseAccessTest_hpp
