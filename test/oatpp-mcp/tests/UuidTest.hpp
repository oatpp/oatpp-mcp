//
// The identifier generator itself: format, randomness and thread safety.
//
// SessionIdTest covers the same properties through Session::getId(); this test covers the
// generator directly so that a failure names the generator rather than its only caller, and so
// that the properties are pinned even if the session code stops using it.
//
// See SECURITY-FINDINGS.md, finding F2.
//

#ifndef oatpp_mcp_test_UuidTest_hpp
#define oatpp_mcp_test_UuidTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * oatpp::mcp::utils::Uuid::generateV4().
 */
class UuidTest : public oatpp::test::UnitTest {
public:

  UuidTest()
    : oatpp::test::UnitTest("TEST[mcp::Uuid]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_UuidTest_hpp
