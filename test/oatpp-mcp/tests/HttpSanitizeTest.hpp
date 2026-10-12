//
// The encoding/validation rules that keep tool arguments out of HTTP framing.
//
// See SECURITY-FINDINGS.md, finding F1.
//

#ifndef oatpp_mcp_test_HttpSanitizeTest_hpp
#define oatpp_mcp_test_HttpSanitizeTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * {@link oatpp::mcp::utils::HttpSanitize}: percent-encoding of request-target values, and rejection
 * of values that cannot be represented as a header.
 */
class HttpSanitizeTest : public oatpp::test::UnitTest {
public:

  HttpSanitizeTest()
    : oatpp::test::UnitTest("TEST[mcp::HttpSanitize]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_HttpSanitizeTest_hpp
