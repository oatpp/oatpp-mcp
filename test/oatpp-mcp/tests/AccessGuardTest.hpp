//
// The Origin/Host policy that decides who may open or address an MCP session.
//
// See SECURITY-FINDINGS.md, finding F4. The two attacks this policy exists for need no credential:
// a page on another site driving a server on the operator's machine (Origin), and an attacker's
// domain resolving to 127.0.0.1 (Host). The second one is only visible to a Host allow-list, so
// the tests pin both what the list does and - just as important - what it is doing when it is not
// configured.
//

#ifndef oatpp_mcp_test_AccessGuardTest_hpp
#define oatpp_mcp_test_AccessGuardTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * Origin and Host validation.
 */
class AccessGuardTest : public oatpp::test::UnitTest {
public:

  AccessGuardTest()
    : oatpp::test::UnitTest("TEST[mcp::AccessGuard]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_AccessGuardTest_hpp
