#include "LogSafeTest.hpp"

#include "TestChecks.hpp"

#include "oatpp-mcp/utils/LogSafe.hpp"

#include <string>
#include <vector>

using oatpp::mcp::test::Checks;
using oatpp::mcp::test::escape;
using oatpp::mcp::utils::LogSafe;

namespace {

struct TextCase {
  const char* what;
  std::string input;
  v_buff_size maxLength;
  std::string expected;
};

/*
 * The policy, pinned: a log record is one line and it is bounded. CR, LF and TAB keep a readable
 * two-character form because they are the characters an operator sometimes genuinely wants to see;
 * everything else that is not printable becomes \xNN. Bytes >= 0x80 pass through - they are most
 * likely UTF-8, and escaping them would make a message in any other script unreadable.
 */
static const std::vector<TextCase> kTextCases = {

  {"a plain value is unchanged",
   "hello world", 1024, "hello world"},

  {"an empty value stays empty",
   "", 1024, ""},

  {"CRLF becomes visible instead of breaking the line",
   "a\r\nb", 1024, "a\\r\\nb"},

  {"a bare LF",
   "a\nb", 1024, "a\\nb"},

  {"a bare CR",
   "a\rb", 1024, "a\\rb"},

  {"a tab",
   "a\tb", 1024, "a\\tb"},

  {"other C0 controls are hex-escaped",
   "\x01\x1F", 1024, "\\x01\\x1f"},

  {"DEL is hex-escaped",
   "\x7F", 1024, "\\x7f"},

  {"NUL is escaped, not treated as a terminator",
   std::string("a\0b", 3), 1024, "a\\x00b"},

  {"UTF-8 text is left readable",
   "café 世界", 1024, "café 世界"},

  {"the F1 payload cannot forge a record",
   "x HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET /users/42 HTTP/1.1\r\n\r\n", 1024,
   "x HTTP/1.1\\r\\nX-Injected: 1\\r\\n\\r\\nGET /users/42 HTTP/1.1\\r\\n\\r\\n"},

  {"a long value is cut, and the cut is reported",
   std::string(5000, 'a'), 100, std::string(100, 'a') + "...[+4900 bytes]"},

  {"a value that exactly fills the budget is not cut",
   std::string(100, 'a'), 100, std::string(100, 'a')},

  {"the budget counts rendered bytes, so one escape may overshoot it",
   "\n\n\n\n\n\n\n\n\n\n", 5, "\\n\\n\\n...[+7 bytes]"},

  {"a cut never lands inside a multi-byte character",
   "aéé", 2, "a...[+4 bytes]"},

  {"a zero budget still says that there was something",
   "abc", 0, "a...[+2 bytes]"},

};

struct SensitiveCase {
  const char* name;
  bool sensitive;
};

static const std::vector<SensitiveCase> kSensitiveNames = {

  {"Authorization",       true},
  {"authorization",       true},
  {"AUTHORIZATION",       true},
  {"Proxy-Authorization", true},
  {"X-Api-Key",           true},
  {"api_key",             true},
  {"apikey",              true},
  {"x-auth-token",        true},
  {"access_token",        true},
  {"Set-Cookie",          true},
  {"Cookie",              true},
  {"password",            true},
  {"client-secret",       true},
  {"X-GitHub-Token",      true},
  {"session_id",          true},
  {"key",                 true},
  {"auth",                true},
  {"token",               true},
  {"secret",              true},
  {"pwd",                 true},

  {"userId",              false},
  {"X-Request-Id",        false},
  {"content-type",        false},
  {"author",              false},   // would match "authorization" only as a substring of it
  {"monkey",              false},   // "key" matches by name, not by substring
  {"keystore",            false},
  {"searchPhrase",        false},
  {"",                    false},

};

struct HeaderCase {
  const char* name;
  const char* value;
  std::string expected;
  const char* what;
};

static const std::vector<HeaderCase> kHeaderCases = {

  {"Authorization", "Bearer supersecret-token-value", "<redacted>",
   "an Authorization value is not written"},
  {"authorization", "x", "<redacted>",
   "the name match is case-insensitive"},
  {"Set-Cookie",    "sid=abc123", "<redacted>",
   "a cookie value is not written"},
  {"X-Trace-Id",    "abc123", "abc123",
   "an ordinary value is written as it is"},
  {"X-Trace-Id",    "a\r\nb", "a\\r\\nb",
   "an ordinary value is still escaped"},
  {"X-Nothing",     nullptr, "(null)",
   "a null value renders instead of crashing"},

};

struct TargetCase {
  const char* what;
  std::string target;
  std::string expected;
};

static const std::vector<TargetCase> kTargetCases = {

  {"a path with no query is unchanged",
   "/users/42", "/users/42"},

  {"an ordinary query is unchanged",
   "/users/offset/1/limit/1/?searchPhrase=hello", "/users/offset/1/limit/1/?searchPhrase=hello"},

  {"a credential in the query is replaced, its name kept",
   "/api?key=SECRETINQUERY&x=1", "/api?key=<redacted>&x=1"},

  {"the name match is case-insensitive and the name keeps its case",
   "/api?Token=abc", "/api?Token=<redacted>"},

  {"every sensitive parameter of several is replaced",
   "/api?a=1&api_key=xyz&b=2&password=p", "/api?a=1&api_key=<redacted>&b=2&password=<redacted>"},

  {"a sensitive name with no value has nothing to redact",
   "/api?secret", "/api?secret"},

  {"an encoded ampersand is not a separator",
   "/api?x=a%26b&key=v", "/api?x=a%26b&key=<redacted>"},

  {"a target that starts at the query still works",
   "?key=v", "?key=<redacted>"},

  {"control characters cannot forge a record",
   "/users/1?searchPhrase=x\r\nFORGED LOG LINE", "/users/1?searchPhrase=x\\r\\nFORGED LOG LINE"},

  {"the whole target stays bounded",
   "/users/" + std::string(1100, 'a'),
   "/users/" + std::string(1017, 'a') + "...[+83 bytes]"},

};

}

void oatpp::mcp::test::LogSafeTest::onRun() {

  Checks checks("TEST[mcp::LogSafe]");

  /*--- text(): escaping and truncation -----------------------------------------------*/

  for(auto& c : kTextCases) {
    auto out = LogSafe::text(oatpp::String(c.input), c.maxLength);
    checks.check(str(out) == c.expected,
                 std::string("text(): ") + c.what,
                 "expected '" + escape(c.expected) + "', got '" + escape(str(out)) + "'");
  }

  {
    auto out = LogSafe::text(static_cast<const char*>(nullptr));
    checks.check(str(out) == "(null)", "text(): a null C string renders instead of crashing",
                 "got '" + escape(str(out)) + "'");
  }

  /*--- nothing that came out of text() may contain a line break ----------------------*/

  for(auto& c : kTextCases) {
    auto out = LogSafe::text(oatpp::String(c.input), c.maxLength);
    checks.check(out != nullptr && out->find('\n') == std::string::npos
                             && out->find('\r') == std::string::npos,
                 "text(): the result of every case is a single line",
                 std::string("case: ") + c.what);
  }

  /*--- isSensitiveName() -------------------------------------------------------------*/

  for(auto& c : kSensitiveNames) {
    checks.check(LogSafe::isSensitiveName(oatpp::String(c.name)) == c.sensitive,
                 std::string("isSensitiveName(\"") + c.name + "\") == "
                 + (c.sensitive ? "true" : "false"));
  }

  checks.check(!LogSafe::isSensitiveName(nullptr), "isSensitiveName(): a null name is not sensitive");

  /*--- headerValue() -----------------------------------------------------------------*/

  for(auto& c : kHeaderCases) {
    auto out = LogSafe::headerValue(oatpp::String(c.name),
                                    c.value == nullptr ? oatpp::String(nullptr)
                                                       : oatpp::String(std::string(c.value)));
    checks.check(str(out) == c.expected, c.what,
                 "expected '" + escape(c.expected) + "', got '" + escape(str(out)) + "'");
  }

  {
    /* The point of redaction, stated as a property rather than as a format. */
    auto out = LogSafe::headerValue("Authorization", "Bearer supersecret-token-value");
    checks.check(str(out).find("supersecret") == std::string::npos,
                 "headerValue(): a redacted value leaves no trace of itself");
  }

  /*--- requestTarget() ---------------------------------------------------------------*/

  for(auto& c : kTargetCases) {
    auto out = LogSafe::requestTarget(oatpp::String(c.target));
    checks.check(str(out) == c.expected, c.what,
                 "expected '" + escape(c.expected) + "', got '" + escape(str(out)) + "'");
  }

  {
    auto out = LogSafe::requestTarget(oatpp::String("/api?key=SECRETINQUERY"));
    checks.check(str(out).find("SECRETINQUERY") == std::string::npos,
                 "requestTarget(): a redacted value leaves no trace of itself");
  }

  {
    auto out = LogSafe::requestTarget(nullptr);
    checks.check(str(out) == "(null)", "requestTarget(): a null target renders instead of crashing");
  }

  checks.assertNoFailures();
}
