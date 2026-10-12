//
// A logger that keeps what it was told instead of printing it.
//
// Extracted from ToolLoggingTest, which was the only test that needed to ask "what did this code
// put in the operator's log?" - a question that comes up again for every finding whose fix is
// "report it instead of swallowing it".
//

#ifndef oatpp_mcp_test_LogCapture_hpp
#define oatpp_mcp_test_LogCapture_hpp

#include "TestChecks.hpp"

#include "oatpp/Environment.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace oatpp { namespace mcp { namespace test {

/** One log record, as it was handed to the logger. */
struct Record {
  v_uint32 priority;
  std::string tag;
  std::string message;
};

/**
 * Everything the process logs while it is installed. `oatpp::Environment::log()` hands every
 * message to the logger and filtering by level happens inside the logger itself, so capturing
 * means saying yes to all priorities - which is also what makes "was this info or debug?" a
 * question this test can answer rather than one it has to infer.
 */
class CapturingLogger : public oatpp::Logger {
private:
  std::mutex m_mutex;
  std::vector<Record> m_records;
public:

  void log(v_uint32 priority, const std::string& tag, const std::string& message) override {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_records.push_back(Record{priority, tag, message});
  }

  bool isLogPriorityEnabled(v_uint32) override {
    return true;
  }

  std::vector<Record> records() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_records;
  }

};

/** Installs a logger for the duration of a scope and puts back whatever was there before. */
class ScopedLogger {
private:
  std::shared_ptr<oatpp::Logger> m_previous;
public:

  explicit ScopedLogger(const std::shared_ptr<oatpp::Logger>& logger)
    : m_previous(oatpp::Environment::getLogger())
  {
    oatpp::Environment::setLogger(logger);
  }

  ~ScopedLogger() {
    oatpp::Environment::setLogger(m_previous);
  }

};

/**
 * Records this test caused - other tests' threads may still be logging into the capture, so a test
 * that installs a logger filters by the tag it logged under.
 */
static inline std::vector<Record> withTag(const std::vector<Record>& records, const std::string& tag) {
  std::vector<Record> result;
  for(auto& r : records) {
    if(r.tag == tag) {
      result.push_back(r);
    }
  }
  return result;
}

/** Records that mention any of these substrings. */
static inline std::vector<Record> withText(const std::vector<Record>& records,
                                           const std::string& needle)
{
  std::vector<Record> result;
  for(auto& r : records) {
    if(r.message.find(needle) != std::string::npos) {
      result.push_back(r);
    }
  }
  return result;
}

static inline std::vector<Record> atPriority(const std::vector<Record>& records, v_uint32 priority) {
  std::vector<Record> result;
  for(auto& r : records) {
    if(r.priority == priority) {
      result.push_back(r);
    }
  }
  return result;
}

/** Everything that was said, as one string - what "nowhere in the log" is checked against. */
static inline std::string transcript(const std::vector<Record>& records) {
  std::string out;
  for(auto& r : records) {
    out += r.message;
    out += "|";
  }
  return out;
}

/** Records as readable text, for the failure message of a check. */
static inline std::string describe(const std::vector<Record>& records) {
  std::string out;
  for(auto& r : records) {
    out += "\n  p" + std::to_string(r.priority) + " '" + escape(r.message) + "'";
  }
  return out;
}

/** A log sink is line-oriented; a record containing a newline is a forged record. */
static inline bool isSingleLine(const std::string& message) {
  return message.find('\n') == std::string::npos && message.find('\r') == std::string::npos;
}

}}}

#endif // oatpp_mcp_test_LogCapture_hpp
