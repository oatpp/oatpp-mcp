#include "UuidTest.hpp"

#include "TestChecks.hpp"

#include "oatpp-mcp/utils/Uuid.hpp"

#include <algorithm>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

/** Longest common prefix of two strings. */
static size_t commonPrefix(const std::string& a, const std::string& b) {
  size_t i = 0;
  while(i < a.size() && i < b.size() && a[i] == b[i]) {
    i ++;
  }
  return i;
}

/** True if the value contains an upper-case hex digit - canonical RFC 4122 form is lowercase. */
static bool hasUpperCaseHex(const std::string& value) {
  return value.find_first_of("ABCDEF") != std::string::npos;
}

}

void oatpp::mcp::test::UuidTest::onRun() {

  Checks checks("TEST[mcp::Uuid]");

  using oatpp::mcp::test::isUuidV4;
  using oatpp::mcp::test::str;

  /*------------------------------------------------------------------------ one value ------*/
  {
    auto value = oatpp::mcp::utils::Uuid::generateV4();

    checks.check(isUuidV4(value), "generateV4() returns a canonical version-4 UUID",
                 "value=" + str(value));
    checks.check(value != nullptr && value->size() == 36,
                 "value is 36 characters", "length=" + std::to_string(value->size()));
    checks.check(value != nullptr && !hasUpperCaseHex(*value),
                 "hex digits are lowercase", "value=" + str(value));

    auto another = oatpp::mcp::utils::Uuid::generateV4();
    checks.check(value != another, "two consecutive draws differ",
                 "both=" + str(value));
  }

  /*--------------------------------------------------------------------- many draws --------*/
  {
    const v_int32 draws = 20000;

    std::unordered_set<std::string> unique;
    unique.reserve(draws);

    std::string previous;
    size_t maxPrefix = 0;
    size_t malformed = 0;
    size_t upperCase = 0;
    bool seenDigit[16] = {false};
    const char* firstOf = "0123456789abcdef";

    for(v_int32 i = 0; i < draws; i++) {
      auto value = oatpp::mcp::utils::Uuid::generateV4();

      if(value == nullptr || !isUuidV4(value)) {
        malformed ++;
        continue;
      }
      if(hasUpperCaseHex(*value)) {
        upperCase ++;
      }

      unique.insert(*value);

      if(!previous.empty()) {
        maxPrefix = std::max(maxPrefix, commonPrefix(previous, *value));
      }
      previous = *value;

      auto c = (*value)[0];
      if(c >= '0' && c <= '9') {
        seenDigit[c - '0'] = true;
      } else if(c >= 'a' && c <= 'f') {
        seenDigit[c - 'a' + 10] = true;
      }
    }

    checks.check(malformed == 0, "every draw is a canonical version-4 UUID",
                 std::to_string(malformed) + " of " + std::to_string(draws) + " malformed");
    checks.check(upperCase == 0, "no draw contains an upper-case hex digit",
                 std::to_string(upperCase) + " of " + std::to_string(draws) + " upper-case");
    checks.check(unique.size() == static_cast<size_t>(draws),
                 "no draw repeats",
                 std::to_string(unique.size()) + " unique of " + std::to_string(draws));

    /*
     * A counter, a timestamp or an address passes "no draw repeats" for a long time. What gives it
     * away is that successive values share their leading digits - the reported session identifiers
     * were heap addresses and shared all 15 characters but the last few. With 122 random bits the
     * chance of two successive draws sharing 9 or more characters is about 20000 / 16^9 ~ 3e-6.
     */
    checks.check(maxPrefix <= 8,
                 "successive draws do not share a long common prefix",
                 "longest common prefix = " + std::to_string(maxPrefix) + " characters");

    bool everyDigitSeen = true;
    std::string missing;
    for(int d = 0; d < 16; d++) {
      if(!seenDigit[d]) {
        everyDigitSeen = false;
        missing += firstOf[d];
      }
    }
    checks.check(everyDigitSeen, "every hex digit appears as the first character",
                 missing.empty() ? "" : "missing: " + missing);
  }

  /*----------------------------------------------------------------- from several threads --*/
  {
    /*
     * The entropy source is a single shared std::random_device, and operator() on one is not
     * required to be thread-safe. Sessions are created on whatever thread serves a request, so
     * this is the normal case rather than an exotic one.
     */
    const v_int32 threads = 4;
    const v_int32 perThread = 2500;

    std::vector<std::vector<std::string>> results(threads);
    std::vector<std::thread> running;

    for(v_int32 t = 0; t < threads; t++) {
      running.emplace_back([&results, t, perThread]{
        for(v_int32 i = 0; i < perThread; i++) {
          auto value = oatpp::mcp::utils::Uuid::generateV4();
          results[t].push_back(value == nullptr ? std::string("<null>") : *value);
        }
      });
    }
    for(auto& t : running) {
      t.join();
    }

    std::unordered_set<std::string> all;
    size_t total = 0;
    size_t malformed = 0;
    for(auto& part : results) {
      for(auto& value : part) {
        total ++;
        if(value.size() != 36) {
          malformed ++;
          continue;
        }
        all.insert(value);
      }
    }

    checks.check(malformed == 0, "concurrent draws are all well-formed",
                 std::to_string(malformed) + " of " + std::to_string(total) + " malformed");
    checks.check(all.size() == total, "concurrent draws are all distinct",
                 std::to_string(all.size()) + " unique of " + std::to_string(total));
  }

  checks.assertNoFailures();
}
