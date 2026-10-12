//
// What the tool call path writes to the log, at which priority, and in what form.
//
// See SECURITY-FINDINGS.md, finding F6.
//

#ifndef oatpp_mcp_test_ToolLoggingTest_hpp
#define oatpp_mcp_test_ToolLoggingTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * {@link oatpp::mcp::utils::LogSafe::logRequest} - the one place
 * {@link oatpp::mcp::capabilities::EndpointTool} renders a request for the log: caller-supplied
 * values never reach it at info, never raw, and never a credential.
 */
class ToolLoggingTest : public oatpp::test::UnitTest {
public:

  ToolLoggingTest()
    : oatpp::test::UnitTest("TEST[mcp::ToolLogging]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_ToolLoggingTest_hpp
