#include "SessionIdTest.hpp"

#include "TestChecks.hpp"

#include "oatpp-mcp/event/Server.hpp"
#include "oatpp-mcp/event/Session.hpp"

#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

/** Sessions are created here to look at their identifiers, not to serve them. */
class NullListener : public oatpp::mcp::event::Session::EventListener {
public:
  void onEvent(oatpp::mcp::event::Session&, const oatpp::mcp::event::Event&) override {}
};

static bool isHexDigit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/**
 * Canonical 8-4-4-4-12 form, version 4, variant 10xx (RFC 4122). Hex case is not constrained.
 */
static bool isUuidV4(const oatpp::String& value) {
  if(value == nullptr || value->size() != 36) {
    return false;
  }
  const char* s = value->c_str();
  static const int hyphens[4] = {8, 13, 18, 23};
  for(int i = 0; i < 36; i++) {
    bool isHyphen = false;
    for(int h = 0; h < 4; h++) {
      isHyphen = isHyphen || (i == hyphens[h]);
    }
    if(isHyphen) {
      if(s[i] != '-') {
        return false;
      }
    } else if(!isHexDigit(s[i])) {
      return false;
    }
  }
  if(s[14] != '4') {
    return false; // version
  }
  return s[19] == '8' || s[19] == '9' || s[19] == 'a' || s[19] == 'b'
      || s[19] == 'A' || s[19] == 'B';                    // variant
}

/** Longest common prefix of two identifiers. */
static size_t commonPrefix(const std::string& a, const std::string& b) {
  size_t i = 0;
  while(i < a.size() && i < b.size() && a[i] == b[i]) {
    i ++;
  }
  return i;
}

/**
 * Close a session and wait for the server to drop it. The session's thread removes it from the
 * registry as its last act, so an absent session is also "thread finished" - which keeps the
 * churn test from accumulating threads.
 */
static void closeAndWait(
  oatpp::mcp::event::Server& server,
  const std::shared_ptr<oatpp::mcp::event::Session>& session
) {
  auto id = session->getId();
  session->close();
  for(int i = 0; i < 500 && server.getSession(id) != nullptr; i++) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

}

void oatpp::mcp::test::SessionIdTest::onRun() {

  Checks checks("TEST[mcp::SessionId]");

  auto listener = std::make_shared<NullListener>();
  oatpp::mcp::event::Server server;

  /*------------------------------------------------------------------ one session ----------*/
  {
    auto session = server.startNewSession(listener);
    auto id = session->getId();

    checks.check(id != nullptr && !id->empty(), "session has a non-empty identifier",
                 "id=" + str(id));
    checks.check(id == session->getId(), "identifier is stable across calls",
                 "first=" + str(id) + ", second=" + str(session->getId()));

    std::string address = std::to_string(reinterpret_cast<v_uint64>(session.get()));
    checks.check(id != nullptr && *id != address,
                 "identifier is not the address of the Session object",
                 "id=" + str(id) + ", &Session=" + address);

    checks.check(isUuidV4(id), "identifier is a version-4 UUID in canonical form",
                 "id=" + str(id));

    closeAndWait(server, session);
    checks.check(server.getSession(id) == nullptr, "closed session is removed from the registry");
  }

  /*--------------------------------------------------------------------------- churn -------*/
  {
    const v_int32 cycles = 200;

    std::vector<std::string> issued;
    std::unordered_set<std::string> unique;
    bool reused = false;

    for(v_int32 i = 0; i < cycles; i++) {
      auto session = server.startNewSession(listener);
      auto id = session->getId();
      if(id == nullptr || !unique.insert(*id).second) {
        reused = true;
      }
      if(id != nullptr) {
        issued.push_back(*id);
      }
      closeAndWait(server, session);
    }

    checks.check(!reused, "no identifier is reissued across create/close cycles",
                 "unique=" + std::to_string(unique.size()) + " of " + std::to_string(cycles));

    /*
     * Identifiers handed out one after the other must not look like the same number with a
     * different low-order part. A heap address - or any counter - fails this immediately: the
     * reported reuse rate came from an allocator that walked a small set of addresses.
     */
    size_t maxPrefix = 0;
    for(size_t i = 1; i < issued.size(); i++) {
      maxPrefix = std::max(maxPrefix, commonPrefix(issued[i - 1], issued[i]));
    }
    checks.check(maxPrefix <= 8,
                 "consecutive identifiers do not share a long common prefix",
                 "longest common prefix = " + std::to_string(maxPrefix) + " characters");
  }

  checks.assertNoFailures();
}
