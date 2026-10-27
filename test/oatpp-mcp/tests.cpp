//
// Test runner for oatpp-mcp.
//
// Usage:
//   module-tests                run every registered test in this process
//   module-tests --test=<Name>  run a single test (this is what CTest uses)
//   module-tests --list         print the registry and exit
//
// Tests are listed in test/CMakeLists.txt (MCP_TESTS) and in the registry below. A name that is in
// one list but not the other fails loudly: CTest fails on the unknown `--test=`, and `--list` is the
// place to look when it does.
//

#include "oatpp-mcp/tests/HttpSanitizeTest.hpp"
#include "oatpp-mcp/tests/ListenerMessageTest.hpp"
#include "oatpp-mcp/tests/SessionIdTest.hpp"
#include "oatpp-mcp/tests/ToolHttpFramingTest.hpp"

#include "oatpp/Environment.hpp"
#include "oatpp/base/Log.hpp"
#include "oatpp-test/UnitTest.hpp"

#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

class TestDescriptor {
public:
  const char* name;
  const char* tag;
  bool leakChecked;
  const char* leakCheckNote;
  std::function<std::shared_ptr<oatpp::test::UnitTest>()> create;
};

/**
 * Tests of this module. Keep in sync with MCP_TESTS in test/CMakeLists.txt.
 */
static std::vector<TestDescriptor> tests() {
  return {
    TestDescriptor{
      "HttpSanitizeTest",
      "TEST[mcp::HttpSanitize]",
      true,
      nullptr,
      [] { return std::static_pointer_cast<oatpp::test::UnitTest>(
        std::make_shared<oatpp::mcp::test::HttpSanitizeTest>()); }
    },
    TestDescriptor{
      "SessionIdTest",
      "TEST[mcp::SessionId]",
      true,
      nullptr,
      [] { return std::static_pointer_cast<oatpp::test::UnitTest>(
        std::make_shared<oatpp::mcp::test::SessionIdTest>()); }
    },
    TestDescriptor{
      "ListenerMessageTest",
      "TEST[mcp::ListenerMessage]",
      true,
      nullptr,
      [] { return std::static_pointer_cast<oatpp::test::UnitTest>(
        std::make_shared<oatpp::mcp::test::ListenerMessageTest>()); }
    },
    TestDescriptor{
      "ToolHttpFramingTest",
      "TEST[mcp::ToolHttpFraming]",
      false,
      "oatpp::mcp::utils::ApiBridge cannot be stopped - its server threads capture `this`, so the "
      "bridge and the objects it owns outlive the test. See SECURITY-FINDINGS.md (F7).",
      [] { return std::static_pointer_cast<oatpp::test::UnitTest>(
        std::make_shared<oatpp::mcp::test::ToolHttpFramingTest>()); }
    },
  };
}

static int runOne(const TestDescriptor& test) {
  auto instance = test.create();

  if(test.leakChecked) {
    instance->run();
    return 0;
  }

  // Same lifecycle as oatpp::test::UnitTest::run(), minus its "no oatpp object may outlive the
  // test" assertion - see the note in the registry.
  OATPP_LOGi(test.tag, "\033[1mSTART\033[0m... (object-leak check disabled: {})",
             test.leakCheckNote ? test.leakCheckNote : "n/a")
  instance->before();
  instance->onRun();
  instance->after();
  OATPP_LOGi(test.tag, "\033[1mFINISHED\033[0m - \033[1;32msuccess!\033[0m")
  return 0;
}

}

int main(int argc, const char* argv[]) {
  std::string selection;
  bool listOnly = false;

  for(int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if(arg == "--list") {
      listOnly = true;
    } else if(arg.rfind("--test=", 0) == 0) {
      selection = arg.substr(std::string("--test=").size());
    } else {
      std::cerr << "usage: " << argv[0] << " [--list] [--test=<TestName>]" << std::endl;
      return 2;
    }
  }

  auto registry = tests();

  if(listOnly) {
    for(auto& t : registry) {
      std::cout << t.name << std::endl;
    }
    return EXIT_SUCCESS;
  }

  oatpp::Environment::init();

  v_int32 run = 0;
  v_int32 failed = 0;
  bool skippedLeakCheck = false;

  for(auto& t : registry) {
    if(!selection.empty() && selection != t.name) {
      continue;
    }
    run ++;
    if(!t.leakChecked) {
      skippedLeakCheck = true;
    }
    try {
      runOne(t);
    } catch (const std::exception& e) {
      failed ++;
      OATPP_LOGe(t.tag, "test threw an unhandled exception: %s", e.what())
    } catch (...) {
      failed ++;
      OATPP_LOGe(t.tag, "test threw an unknown exception")
    }
  }

  if(run == 0) {
    if(selection.empty()) {
      std::cout << "no tests registered" << std::endl;
      oatpp::Environment::destroy();
      return EXIT_SUCCESS;
    }
    std::cerr << "no such test: '" << selection << "'. Available:" << std::endl;
    for(auto& t : registry) {
      std::cerr << "  " << t.name << std::endl;
    }
    oatpp::Environment::destroy();
    return 2;
  }

  // The global leak check is only meaningful if every test in this process was able to release
  // everything it allocated.
  if(!skippedLeakCheck) {
    OATPP_ASSERT(oatpp::Environment::getObjectsCount() == 0)
  }

  oatpp::Environment::destroy();

  std::cout << (failed == 0 ? "OK" : "FAILED") << " - " << run << " test(s) run, "
            << failed << " failed" << std::endl;
  return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
