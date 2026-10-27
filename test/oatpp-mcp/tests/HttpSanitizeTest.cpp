#include "HttpSanitizeTest.hpp"

#include "TestChecks.hpp"

#include "oatpp-mcp/utils/HttpSanitize.hpp"

#include <stdexcept>
#include <string>

namespace {

using oatpp::mcp::utils::HttpSanitize;

struct Case {
  const char* input;
  const char* expected;
};

/*
 * The policy, pinned: RFC 3986 unreserved plus !'()* survive, everything else is percent-encoded
 * with uppercase hex - including '%', which means input is always treated as raw and an already
 * encoded value is deliberately double-encoded.
 */
static const Case kEncodings[] = {

  {"hello",              "hello"},
  {"",                   ""},
  {"a-._~!*'()",         "a-._~!*'()"},

  {"a b",                "a%20b"},
  {"a/b",                "a%2Fb"},
  {"a?b",                "a%3Fb"},
  {"a#b",                "a%23b"},
  {"a:b",                "a%3Ab"},
  {"a@b",                "a%40b"},
  {"a,b;c",              "a%2Cb%3Bc"},

  {"a&b=c+d#e",          "a%26b%3Dc%2Bd%23e"},

  {"100%",               "100%25"},
  {"a%20b",              "a%2520b"},

  {"/users/42",          "%2Fusers%2F42"},
  {"\r\n",               "%0D%0A"},
  {"x\r\n\r\nGET /x HTTP/1.1",
   "x%0D%0A%0D%0AGET%20%2Fx%20HTTP%2F1.1"},

  {"ü",                  "%C3%BC"},

};

struct HeaderCase {
  const char* name;          // nullptr => null name
  const char* value;         // nullptr => null value
  bool valid;
  const char* description;
};

static const HeaderCase kHeaders[] = {

  {"X-Test",     "v",                              true,  "a plain header"},
  {"X-Test",     "bearer abc123",                  true,  "spaces inside a value"},
  {"X-Test",     "café",                           true,  "obs-text (UTF-8) is allowed"},
  {"X-Test",     nullptr,                          true,  "a null value is not an invalid one"},
  {"X-Test-1_2", "v",                              true,  "digits, '-' and '_' are token chars"},

  {"X-Test",     "v\r\nX-Injected: pwned",         false, "CRLF injects a header"},
  {"X-Test",     "v\nX-Injected: pwned",           false, "a bare LF ends the value"},
  {"X-Test",     "v\r",                            false, "a bare CR"},
  {"X-Test",     "v\tb",                           false, "HTAB is not field-vchar"},
  {"X-Test",     "\x01",                           false, "a C0 control"},
  {"X-Test",     "\x7F",                           false, "DEL"},

  {"X Test",     "v",                              false, "a space is not a field-name char"},
  {"X\r\nTest",  "v",                              false, "CRLF in the name"},
  {"",           "v",                              false, "an empty name"},
  {nullptr,      "v",                              false, "a null name"},

};

/** True if the call throws std::invalid_argument - and nothing else. */
template<class F>
static bool rejects(F f) {
  try {
    f();
  } catch (const std::invalid_argument&) {
    return true;
  } catch (...) {
    return false;
  }
  return false;
}

}

void oatpp::mcp::test::HttpSanitizeTest::onRun() {

  Checks checks("TEST[mcp::HttpSanitize]");

  /*------------------------------------------------------------------ encoding ----------*/
  for(const auto& c : kEncodings) {
    auto path = HttpSanitize::encodePathSegment(oatpp::String(c.input));
    checks.check(str(path) == c.expected,
                 std::string("encodePathSegment(\"") + escape(c.input) + "\")",
                 "expected '" + escape(c.expected) + "', got '" + escape(str(path)) + "'");

    auto query = HttpSanitize::encodeQueryComponent(oatpp::String(c.input));
    checks.check(str(query) == c.expected,
                 std::string("encodeQueryComponent(\"") + escape(c.input) + "\")",
                 "expected '" + escape(c.expected) + "', got '" + escape(str(query)) + "'");
  }

  checks.check(HttpSanitize::encodePathSegment(nullptr) == nullptr,
               "encodePathSegment(nullptr) stays nullptr rather than inventing a value");
  checks.check(HttpSanitize::encodeQueryComponent(nullptr) == nullptr,
               "encodeQueryComponent(nullptr) stays nullptr rather than inventing a value");

  /*------------------------------------------------------------------ headers -----------*/
  for(const auto& c : kHeaders) {
    oatpp::String name = c.name == nullptr ? oatpp::String() : oatpp::String(c.name);
    oatpp::String value = c.value == nullptr ? oatpp::String() : oatpp::String(c.value);

    bool rejected = rejects([&]{ HttpSanitize::validateHeaderField(name, value); });

    checks.check(rejected == !c.valid,
                 std::string(c.valid ? "accepts " : "rejects ") + c.description,
                 std::string("name='") + escape(c.name ? c.name : "(null)") +
                 "', value='" + escape(c.value ? c.value : "(null)") + "'");
  }

  /*
   * A NUL that is really there: a `const char*` in the table above would stop at it, so this one
   * has to be built with an explicit length.
   */
  {
    auto withNul = oatpp::String(std::make_shared<std::string>("v\0broken", 8));
    checks.check(withNul != nullptr && withNul->size() == 8, "the test built a value with an embedded NUL");
    checks.check(rejects([&]{ HttpSanitize::validateHeaderField(oatpp::String("X-Test"), withNul); }),
                 "rejects an embedded NUL");
  }

  /*--------------------------------------------------------------- request target -------*/
  checks.check(!rejects([&]{ HttpSanitize::validateRequestTarget(oatpp::String("/users/1?q=a%20b")); }),
               "validateRequestTarget accepts a normal target");
  checks.check(rejects([&]{ HttpSanitize::validateRequestTarget(oatpp::String("/users/1\r\n\r\nPOST /x")); }),
               "validateRequestTarget rejects a target with CRLF");
  checks.check(rejects([&]{ HttpSanitize::validateRequestTarget(oatpp::String("/users/1\n")); }),
               "validateRequestTarget rejects a target with a bare LF");
  checks.check(!rejects([&]{ HttpSanitize::validateRequestTarget(nullptr); }),
               "validateRequestTarget accepts a null target");

  checks.assertNoFailures();
}
