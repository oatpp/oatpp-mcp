//
// Session identifiers must not be guessable, and must not be derivable from server state.
//
// See SECURITY-FINDINGS.md, finding F2: `Session::getId()` used to return the decimal address of
// the Session object, which is (a) trivially predictable and (b) recycled by the allocator, so a
// client could be handed the identifier of a session that a later client would open.
//

#ifndef oatpp_mcp_test_SessionIdTest_hpp
#define oatpp_mcp_test_SessionIdTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * Session identifier generation.
 */
class SessionIdTest : public oatpp::test::UnitTest {
public:

  SessionIdTest()
    : oatpp::test::UnitTest("TEST[mcp::SessionId]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_SessionIdTest_hpp
