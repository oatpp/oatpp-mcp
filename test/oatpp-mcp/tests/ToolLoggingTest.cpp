#include "ToolLoggingTest.hpp"

#include "LogCapture.hpp"
#include "TestChecks.hpp"

#include "oatpp-mcp/utils/LogSafe.hpp"

#include "oatpp/Environment.hpp"
#include "oatpp/web/protocol/http/Http.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

using oatpp::mcp::test::Checks;
using oatpp::mcp::test::escape;
using oatpp::mcp::utils::LogSafe;

namespace {

using oatpp::mcp::test::CapturingLogger;
using oatpp::mcp::test::Record;
using oatpp::mcp::test::ScopedLogger;
using oatpp::mcp::test::atPriority;
using oatpp::mcp::test::describe;
using oatpp::mcp::test::isSingleLine;
using oatpp::mcp::test::transcript;
using oatpp::mcp::test::withTag;

/* The capture itself lives in LogCapture.hpp - the logger is a process-wide object, so there is
   exactly one implementation of it worth having. */

/* Distinct from the unit test's own tag: these are records this test caused, not records about it. */
const char* const kTag = "TEST[mcp::ToolLogging::captured]";

const char* const kSecretHeader = "Bearer supersecret-token-value";
const char* const kSecretQuery = "SECRETINQUERY";
const char* const kSecretBody = "BODYSECRETPAYLOAD";
const char* const kResolvedValue = "4242";

/** The F1 payload: a second request where a search phrase belonged. */
std::string injectionTarget() {
  return std::string("/users/") + kResolvedValue
       + "?searchPhrase=x HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET /users/99 HTTP/1.1\r\n\r\n"
       + "&api_key=" + kSecretQuery;
}

void logOneRequest(const std::shared_ptr<CapturingLogger>& /*capture*/) {
  oatpp::web::protocol::http::Headers headers;
  headers.put("Authorization", kSecretHeader);
  headers.put("X-Plain", "a\r\nb");

  LogSafe::logRequest(kTag,
                      "getUserById",
                      "GET",
                      "/users/{userId}",
                      oatpp::String(injectionTarget()),
                      headers,
                      oatpp::String(std::string("{\"note\":\"") + kSecretBody + "\"}"));
}

}

void oatpp::mcp::test::ToolLoggingTest::onRun() {

  Checks checks("TEST[mcp::ToolLogging]");

  auto capture = std::make_shared<CapturingLogger>();
  {
    ScopedLogger scope(capture);
    logOneRequest(capture);
  }

  auto mine = withTag(capture->records(), kTag);
  auto all = transcript(mine);

  /*--- shape ------------------------------------------------------------------------*/

  checks.check(mine.size() == 5,
               "one endpoint line, one target, two headers and one body",
               "captured " + std::to_string(mine.size()) + " records:" + describe(mine));

  for(auto& r : mine) {
    checks.check(isSingleLine(r.message),
                 "no record spans more than one line",
                 "p" + std::to_string(r.priority) + " '" + escape(r.message) + "'");
  }

  /*--- what info may contain --------------------------------------------------------*/

  auto infos = atPriority(mine, oatpp::Logger::PRIORITY_I);

  checks.check(infos.size() == 1,
               "exactly one info-level record per tool call",
               std::to_string(infos.size()) + " records:" + describe(infos));

  if(!infos.empty()) {
    const std::string& info = infos[0].message;
    checks.check(info.find("getUserById") != std::string::npos
                 && info.find("/users/{userId}") != std::string::npos,
                 "the info line says which endpoint ran, by name and by pattern",
                 "'" + escape(info) + "'");

    /*
     * Which tool ran is the operator's question - with a proxy blocking tools it is also the
     * security question - so it survives the default log level. What the caller sent does not:
     * every one of these is a value the tool call supplied.
     */
    checks.check(info.find(kResolvedValue) == std::string::npos,
                 "the info line does not contain the resolved path",
                 "'" + escape(info) + "'");
    checks.check(info.find(kSecretQuery) == std::string::npos,
                 "the info line does not contain the query",
                 "'" + escape(info) + "'");
    checks.check(info.find(kSecretHeader) == std::string::npos,
                 "the info line does not contain any header value",
                 "'" + escape(info) + "'");
    checks.check(info.find(kSecretBody) == std::string::npos,
                 "the info line does not contain the body",
                 "'" + escape(info) + "'");
    checks.check(info.find("X-Injected") == std::string::npos,
                 "the info line does not contain the injected text",
                 "'" + escape(info) + "'");
  }

  /*--- what debug may contain, and in what form -------------------------------------*/

  auto debugs = atPriority(mine, oatpp::Logger::PRIORITY_D);

  checks.check(!debugs.empty(), "the resolved request is still traceable at debug",
               "records:" + describe(mine));
  checks.check(all.find("x HTTP/1.1\\r\\nX-Injected: 1") != std::string::npos,
               "the injected text is in the log as text, escaped",
               "transcript: '" + escape(all) + "'");
  checks.check(all.find("x HTTP/1.1\r\nX-Injected: 1") == std::string::npos,
               "and not as the framing it was meant to be",
               "transcript: '" + escape(all) + "'");
  checks.check(all.find("a\\r\\nb") != std::string::npos,
               "an ordinary header value is escaped too",
               "transcript: '" + escape(all) + "'");

  /*--- what no priority may contain --------------------------------------------------*/

  checks.check(all.find(kSecretHeader) == std::string::npos,
               "an Authorization value is nowhere in the log",
               "transcript: '" + escape(all) + "'");
  checks.check(all.find(kSecretQuery) == std::string::npos,
               "a credential passed as a query parameter is nowhere in the log",
               "transcript: '" + escape(all) + "'");
  checks.check(all.find("<redacted>") != std::string::npos,
               "a redaction is visible as a redaction",
               "transcript: '" + escape(all) + "'");

  {
    /* The body is not redacted - it is what you came to look at - but it is debug-only. */
    bool bodyAtDebug = false;
    for(auto& r : mine) {
      if(r.message.find(kSecretBody) != std::string::npos) {
        checks.check(r.priority == oatpp::Logger::PRIORITY_D,
                     "the request body is logged at debug only",
                     "found at p" + std::to_string(r.priority));
        bodyAtDebug = true;
      }
    }
    checks.check(bodyAtDebug, "the request body is traceable at debug");
  }

  /*--- nothing is exempt, not even the endpoint description --------------------------*/

  {
    auto second = std::make_shared<CapturingLogger>();
    {
      ScopedLogger scope(second);

      oatpp::web::protocol::http::Headers headers;

      /*
       * An endpoint's name and path pattern are written by whoever exposed it as a tool, which is
       * the definition of trusted in this codebase and not a very long list. They are rendered the
       * same way as everything else, so this is a property of the code rather than of this input.
       */
      LogSafe::logRequest(kTag,
                          "evil\nname",
                          "GET",
                          "/p{v}\r\nforged",
                          oatpp::String("/p1"),
                          headers,
                          nullptr);
    }

    auto mine2 = withTag(second->records(), kTag);
    checks.check(mine2.size() == 2,
                 "no body, no body record",
                 "captured " + std::to_string(mine2.size()) + " records:" + describe(mine2));
    for(auto& r : mine2) {
      checks.check(isSingleLine(r.message),
                   "an endpoint name or pattern cannot forge a log line either",
                   "p" + std::to_string(r.priority) + " '" + escape(r.message) + "'");
    }
    auto transcript2 = transcript(mine2);
    checks.check(transcript2.find("evil\\nname") != std::string::npos,
                 "and is still readable",
                 "transcript: '" + escape(transcript2) + "'");
  }

  checks.assertNoFailures();
}
