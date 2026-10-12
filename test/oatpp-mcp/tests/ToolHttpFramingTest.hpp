//
// Tool arguments must not become HTTP framing.
//
// See SECURITY-FINDINGS.md, finding F1: `EndpointTool` builds an HTTP request out of the tool
// arguments and hands it to an oatpp `HttpRequestExecutor`. Path variables are substituted raw by
// `oatpp::web::url::mapping::Pattern::reconstruct()`, query values are appended raw, and header
// values are put into the header map raw - and nothing on the way out rejects CR or LF. A tool
// argument can therefore terminate the request line or the header block and start a new request,
// which the upstream executes as if the MCP client had sent it.
//
// The assertions below are about what the *upstream endpoint observed*, not about what the tool
// returned: the whole point of the attack is that the caller gets a perfectly normal answer.
//

#ifndef oatpp_mcp_test_ToolHttpFramingTest_hpp
#define oatpp_mcp_test_ToolHttpFramingTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * HTTP request construction in oatpp::mcp::capabilities::EndpointTool.
 */
class ToolHttpFramingTest : public oatpp::test::UnitTest {
public:

  ToolHttpFramingTest()
    : oatpp::test::UnitTest("TEST[mcp::ToolHttpFraming]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_ToolHttpFramingTest_hpp
