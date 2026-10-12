#include "AccessGuardTest.hpp"

#include "TestChecks.hpp"

#include "oatpp-mcp/utils/AccessGuard.hpp"

#include <initializer_list>
#include <string>
#include <vector>

using oatpp::mcp::test::Checks;
using oatpp::mcp::test::str;
using oatpp::mcp::utils::AccessGuard;

namespace {

/** One policy, and one request put to it. */
struct Row {
  const char* description;
  AccessGuard::Config config;
  const char* origin;    ///< nullptr: the request carried no Origin header
  const char* host;      ///< nullptr: the request carried no Host header
  bool allowed;          ///< expected outcome
  v_int32 status;        ///< expected status code when refused; ignored when allowed
  /**
   * Expected reason when refused; nullptr: any reason. Worth pinning where the reason is the
   * whole difference between two refusals - an operator reading a log wants to know which rule
   * fired, and "Origin is not allowed" and "Origin 'null' is not allowed" are different answers.
   */
  const char* reason = nullptr;
};

static AccessGuard::Config withHosts(std::initializer_list<const char*> entries) {
  AccessGuard::Config config;
  for(const auto& entry : entries) {
    config.allowedHosts.push_back(oatpp::String(entry));
  }
  return config;
}

static AccessGuard::Config withOrigins(std::initializer_list<const char*> entries) {
  AccessGuard::Config config;
  for(const auto& entry : entries) {
    config.allowedOrigins.push_back(oatpp::String(entry));
  }
  return config;
}

static const std::vector<Row> kRows = {

  /*--- the default policy: Origin must agree, Host is not restricted ----------------------*/

  {"a native client that sends no Origin is let through",
   AccessGuard::Config(), nullptr, "localhost:3001", true, 0},

  {"an empty Origin header is treated as absent",
   AccessGuard::Config(), "", "localhost:3001", true, 0},

  {"a same-origin browser request is let through",
   AccessGuard::Config(), "http://localhost:3001", "localhost:3001", true, 0},

  {"a cross-origin browser request is refused",
   AccessGuard::Config(), "http://evil.example", "localhost:3001", false, 403,
   "Origin is not allowed"},

  {"an https origin agrees with the same host",
   AccessGuard::Config(), "https://mcp.example.com", "mcp.example.com", true, 0},

  /*
   * The scheme of the origin is deliberately not compared with anything: TLS terminated in front of
   * this server means the page is https while the Host header says nothing about it. Pinning this
   * keeps a future "harden it a bit more" change from breaking every TLS deployment instead.
   */
  {"the origin scheme is not what is checked",
   AccessGuard::Config(), "https://localhost:3001", "localhost:3001", true, 0},

  {
   /*
    * A `null` origin would be refused by the ordinary rules too - it is not self and it is not
    * named - so what this row protects is the message, which is the part an operator acts on: a
    * sandboxed frame is a different diagnosis from a wrong allow-list.
    */
   "Origin: null is refused, and says so",
   AccessGuard::Config(), "null", "localhost:3001", false, 403,
   "Origin 'null' is not allowed"},

  {"an origin cannot agree with a Host that is not there",
   AccessGuard::Config(), "http://localhost:3001", nullptr, false, 403,
   "Origin is not allowed"},

  {"a path on the end of an origin does not confuse the comparison",
   AccessGuard::Config(), "http://localhost:3001/", "localhost:3001", true, 0},

  {"optional whitespace around the header values is tolerated",
   AccessGuard::Config(), "  http://localhost:3001  ", " localhost:3001 ", true, 0},

  {"an origin with no scheme is not an origin",
   AccessGuard::Config(), "localhost:3001", "localhost:3001", false, 403},

  {"a non-http origin has to be allowed by name",
   AccessGuard::Config(), "chrome-extension://nkeimhogjdpnpcefljghhfjflbdnpjof",
   "localhost:3001", false, 403},

  {"a non-http origin named in the list is accepted",
   withOrigins({"chrome-extension://nkeimhogjdpnpcefljghhfjflbdnpjof"}),
   "chrome-extension://nkeimhogjdpnpcefljghhfjflbdnpjof",
   "localhost:3001", true, 0},

  /*--- the Host allow-list -------------------------------------------------------------*/

  {"Host allow-list: an exact match is accepted",
   withHosts({"localhost:3001"}), nullptr, "localhost:3001", true, 0},

  {"Host allow-list: matching is case-insensitive",
   withHosts({"localhost:3001"}), nullptr, "LocalHost:3001", true, 0},

  {"Host allow-list: an entry with no port accepts any port",
   withHosts({"localhost"}), nullptr, "localhost:9999", true, 0},

  {"Host allow-list: an entry with a port requires it",
   withHosts({"localhost:3001"}), nullptr, "localhost:3002", false, 403},

  {"Host allow-list: a different host is refused",
   withHosts({"localhost:3001"}), nullptr, "example.com", false, 403, "Host is not allowed"},

  /*
   * The shape of mistake this list is most likely to be written against: a suffix that reads as the
   * allowed name to something matching loosely.
   */
  {"Host allow-list: matching is not a prefix or suffix match",
   withHosts({"localhost"}), nullptr, "localhost.evil.example", false, 403},

  {"Host allow-list: an IPv6 literal with a port",
   withHosts({"[::1]:3001"}), nullptr, "[::1]:3001", true, 0},

  {"Host allow-list: an IPv6 literal entry with no port accepts any port",
   withHosts({"[::1]"}), nullptr, "[::1]:1234", true, 0},

  {"Host allow-list: an IPv6 literal does not match another port",
   withHosts({"[::1]:3001"}), nullptr, "[::1]:3002", false, 403},

  {"Host allow-list: a missing Host header is a 400, not a 403",
   withHosts({"localhost"}), nullptr, nullptr, false, 400, "Missing Host header"},

  {"Host allow-list: several entries, the second one matches",
   withHosts({"mcp.example.com", "localhost"}), nullptr, "localhost:3001", true, 0},

  /*--- DNS rebinding: the point of the Host allow-list ---------------------------------*/

  {
   /*
    * The attacker's domain resolves to 127.0.0.1, so the browser sends its own name as the Host and
    * an Origin that agrees with it. Nothing about the pair is inconsistent - which is exactly why
    * the Origin check cannot see this, and why the list below is what saves the deployment.
    */
   "DNS rebinding: the Host allow-list refuses a name it does not know",
   withHosts({"localhost", "127.0.0.1"}),
   "http://rebound.attacker.example:3001", "rebound.attacker.example:3001", false, 403,
   "Host is not allowed"},

  {
   /*
    * The same request against the default configuration is accepted, and this row exists to keep
    * that honest: leaving allowedHosts empty is a decision with a named consequence, not a safe
    * default that happens to be convenient.
    */
   "DNS rebinding: with no Host allow-list configured, nothing here stops it",
   AccessGuard::Config(),
   "http://rebound.attacker.example:3001", "rebound.attacker.example:3001", true, 0},

  /*--- turning the Origin check off ----------------------------------------------------*/

  {"checkOrigin=false lets a cross-origin request through",
   [] { AccessGuard::Config c; c.checkOrigin = false; return c; }(),
   "http://evil.example", "localhost:3001", true, 0},

  {"checkOrigin=false still enforces the Host allow-list",
   [] { AccessGuard::Config c; c.checkOrigin = false; c.allowedHosts.push_back("localhost"); return c; }(),
   "http://localhost:3001", "evil.example", false, 403},

  /*--- an explicitly allowed origin ----------------------------------------------------*/

  {"an allowed origin is accepted although it is not this server's own",
   withOrigins({"http://app.example:8080"}), "http://app.example:8080", "localhost:3001", true, 0},

  {"allowed origins are matched case-insensitively",
   withOrigins({"http://App.Example:8080"}), "http://app.example:8080", "localhost:3001", true, 0},

  {"an origin that is merely similar to an allowed one is refused",
   withOrigins({"http://app.example:8080"}), "http://app.example.evil:8080", "localhost:3001",
   false, 403},

};

}

void oatpp::mcp::test::AccessGuardTest::onRun() {

  Checks checks("TEST[mcp::AccessGuard]");

  for(const auto& row : kRows) {

    AccessGuard guard(row.config);

    AccessGuard::Decision decision;
    std::string thrown;
    try {
      decision = guard.check(row.origin == nullptr ? nullptr : oatpp::String(row.origin),
                             row.host == nullptr ? nullptr : oatpp::String(row.host));
    } catch (const std::exception& e) {
      thrown = e.what();
    }

    checks.check(thrown.empty(),
                 std::string("check() does not throw: ") + row.description,
                 "thrown: " + thrown);

    checks.check(decision.allowed == row.allowed,
                 row.description,
                 "allowed=" + std::string(decision.allowed ? "true" : "false")
                   + ", status=" + std::to_string(decision.status.code)
                   + ", reason='" + str(decision.reason) + "'"
                   + ", origin='" + std::string(row.origin != nullptr ? row.origin : "(none)")
                   + "', host='" + std::string(row.host != nullptr ? row.host : "(none)") + "'");

    if(!row.allowed) {
      checks.check(decision.status.code == row.status,
                   std::string("refusal answers the expected status: ") + row.description,
                   "status=" + std::to_string(decision.status.code)
                     + ", expected=" + std::to_string(row.status));
      checks.check(decision.reason != nullptr && !decision.reason->empty(),
                   std::string("refusal says which rule fired: ") + row.description,
                   "reason='" + str(decision.reason) + "'");
      if(row.reason != nullptr) {
        checks.check(str(decision.reason) == row.reason,
                     std::string("refusal names the expected rule: ") + row.description,
                     "reason='" + str(decision.reason) + "', expected='" + row.reason + "'");
      }
    } else {
      checks.check(decision.allowed,
                   std::string("an allowed decision is not also a refusal: ") + row.description);
    }
  }

  /*--- the two rules on their own, away from any policy ----------------------------------*/

  checks.check(AccessGuard::hostMatches("localhost:3001", "LOCALHOST"),
               "hostMatches(): a portless entry matches any port");
  checks.check(!AccessGuard::hostMatches("localhost:3001", "localhost:3001.evil"),
               "hostMatches(): no suffix matching");
  checks.check(!AccessGuard::hostMatches("evil.localhost", "localhost"),
               "hostMatches(): no prefix matching");
  checks.check(!AccessGuard::hostMatches("", "localhost"),
               "hostMatches(): an empty Host matches nothing named");

  checks.check(AccessGuard::originIsSelf("http://localhost:3001", "localhost:3001"),
               "originIsSelf(): origin and host agree");
  checks.check(!AccessGuard::originIsSelf("http://localhost:3001", "localhost:3002"),
               "originIsSelf(): a different port is not the same origin");
  checks.check(!AccessGuard::originIsSelf("http://localhost:3001", nullptr),
               "originIsSelf(): no Host is not the same origin");
  checks.check(!AccessGuard::originIsSelf("gopher://localhost:3001", "localhost:3001"),
               "originIsSelf(): only http and https have origins here");

  checks.assertNoFailures();
}
