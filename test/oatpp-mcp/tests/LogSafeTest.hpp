//
// The rules for putting untrusted text into a log line.
//
// See SECURITY-FINDINGS.md, finding F6.
//

#ifndef oatpp_mcp_test_LogSafeTest_hpp
#define oatpp_mcp_test_LogSafeTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * {@link oatpp::mcp::utils::LogSafe}: control characters cannot forge a log record, a value cannot
 * make a record arbitrarily long, and the values that name a credential are not written at all.
 */
class LogSafeTest : public oatpp::test::UnitTest {
public:

  LogSafeTest()
    : oatpp::test::UnitTest("TEST[mcp::LogSafe]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_LogSafeTest_hpp
