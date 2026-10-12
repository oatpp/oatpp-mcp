//
// Assertion helpers shared by the oatpp-mcp test suite.
//

#ifndef oatpp_mcp_test_TestChecks_hpp
#define oatpp_mcp_test_TestChecks_hpp

#include "oatpp/base/Log.hpp"
#include "oatpp/Types.hpp"

#include <chrono>
#include <string>
#include <thread>

namespace oatpp { namespace mcp { namespace test {

/**
 * Collects the outcome of several related assertions and fails the enclosing unit test once, at the
 * end of the run.
 *
 * `OATPP_ASSERT` terminates the process on the first failed expression. That is the right thing for
 * a precondition, and the wrong thing for a table-driven test: one failing row would hide every row
 * below it. The security regressions in this suite are table-driven, so they record every failure
 * and assert on the total.
 */
class Checks {
private:
  const char* m_tag;
  v_int32 m_total;
  v_int32 m_failed;
public:

  explicit Checks(const char* tag)
    : m_tag(tag)
    , m_total(0)
    , m_failed(0)
  {}

  /**
   * Record the outcome of one check.
   * @param condition - the condition that was expected to hold.
   * @param what - human-readable description of the expectation.
   * @param details - extra context, printed only when the check fails.
   */
  void check(bool condition, const std::string& what, const std::string& details = std::string()) {
    m_total ++;
    if(condition) {
      return;
    }
    m_failed ++;
    if(details.empty()) {
      OATPP_LOGe(m_tag, "\033[1;31mFAILED\033[0m: {}", what.c_str())
    } else {
      OATPP_LOGe(m_tag, "\033[1;31mFAILED\033[0m: {} | {}", what.c_str(), details.c_str())
    }
  }

  /** Number of recorded checks. */
  v_int32 total() const {
    return m_total;
  }

  /** Number of failed checks. */
  v_int32 failed() const {
    return m_failed;
  }

  /**
   * Summarize and fail the enclosing unit test if anything failed.
   * Terminates the process - call it last.
   */
  void assertNoFailures() {
    OATPP_LOGi(m_tag, "{}/{} checks passed", m_total - m_failed, m_total)
    OATPP_ASSERT(m_failed == 0)
  }

};

/**
 * Wait for a condition that becomes true on another thread.
 *
 * Polls, because every condition here is an "eventually", and re-reads the predicate once more after
 * the deadline so that the caller can put the result straight into a check without a second read
 * racing with the timeout.
 */
template<class Predicate>
static bool waitFor(Predicate predicate, v_int32 timeoutMillis, v_int32 stepMillis = 20) {
  for(v_int32 waited = 0; waited < timeoutMillis; waited += stepMillis) {
    if(predicate()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(stepMillis));
  }
  return predicate();
}

/**
 * Printable form of an `oatpp::String`, with `nullptr` made visible instead of crashing the test
 * that printed it.
 */
static inline std::string str(const oatpp::String& value) {
  if(value == nullptr) {
    return "(null)";
  }
  return *value;
}

/**
 * Canonical 8-4-4-4-12 form, version 4, variant 10xx (RFC 4122). Hex case is not constrained.
 */
static inline bool isUuidV4(const oatpp::String& value) {
  if(value == nullptr || value->size() != 36) {
    return false;
  }
  const char* s = value->c_str();
  static const int hyphens[4] = {8, 13, 18, 23};
  auto hexDigit = [](char c) {
    // not isxdigit(): locale-dependent, and it accepts more than RFC 4122 does
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  };
  for(int i = 0; i < 36; i++) {
    bool isHyphen = false;
    for(int h = 0; h < 4; h++) {
      isHyphen = isHyphen || (i == hyphens[h]);
    }
    if(isHyphen) {
      if(s[i] != '-') {
        return false;
      }
    } else if(!hexDigit(s[i])) {
      return false;
    }
  }
  if(s[14] != '4') {
    return false; // version
  }
  return s[19] == '8' || s[19] == '9' || s[19] == 'a' || s[19] == 'b'
      || s[19] == 'A' || s[19] == 'B';                    // variant
}

/**
 * Printable form of a string with control characters escaped, so that a test failure involving
 * CR/LF injection says what actually happened instead of drawing a line break.
 */
static inline std::string escape(const std::string& value) {
  std::string result;
  result.reserve(value.size() + 8);
  for(char c : value) {
    switch(c) {
      case '\r': result += "\\r"; break;
      case '\n': result += "\\n"; break;
      case '\t': result += "\\t"; break;
      default:
        if(static_cast<unsigned char>(c) < 0x20) {
          static const char* hex = "0123456789abcdef";
          result += "\\x";
          result += hex[(static_cast<unsigned char>(c) >> 4) & 0xF];
          result += hex[static_cast<unsigned char>(c) & 0xF];
        } else {
          result += c;
        }
    }
  }
  return result;
}

}}}

#endif // oatpp_mcp_test_TestChecks_hpp
