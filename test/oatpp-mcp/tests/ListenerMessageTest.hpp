//
// A malformed message must not take the server down.
//
// See SECURITY-FINDINGS.md, finding F3: `Listener::onEvent()` and the per-method handlers map and
// remap untrusted JSON outside of any `try`, on a detached session thread. Any `MappingError`
// therefore reaches `std::terminate` and aborts the process. The disclosed PoC (an empty POST body)
// is one instance of a general missing error path - the corpus below is what a few minutes of
// probing turned up.
//

#ifndef oatpp_mcp_test_ListenerMessageTest_hpp
#define oatpp_mcp_test_ListenerMessageTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace mcp { namespace test {

/**
 * Message handling of {@link oatpp::mcp::Listener}: no input may escape as an exception, and a
 * request that carries an `id` must be answered.
 */
class ListenerMessageTest : public oatpp::test::UnitTest {
public:

  ListenerMessageTest()
    : oatpp::test::UnitTest("TEST[mcp::ListenerMessage]")
  {}

  void onRun() override;

};

}}}

#endif // oatpp_mcp_test_ListenerMessageTest_hpp
