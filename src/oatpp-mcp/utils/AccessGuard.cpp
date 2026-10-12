#include "AccessGuard.hpp"

#include <algorithm>
#include <cctype>

namespace oatpp { namespace mcp { namespace utils {

namespace {

/** ASCII-lowercase copy. Header values are compared case-insensitively; bytes >= 0x80 are kept. */
std::string lowered(const oatpp::String& value) {
  std::string result;
  if(value == nullptr) {
    return result;
  }
  result.assign(value->data(), value->size());
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return result;
}

/** Strip whitespace, as a header value may carry optional OWS. */
std::string trimmed(const std::string& value) {
  auto begin = value.begin();
  while(begin != value.end() && (*begin == ' ' || *begin == '\t')) {
    ++ begin;
  }
  auto end = value.end();
  while(end != begin && (*(end - 1) == ' ' || *(end - 1) == '\t')) {
    -- end;
  }
  return std::string(begin, end);
}

/**
 * `example.com:8080` -> {`example.com`, `8080`}, `[::1]:8080` -> {`::1`, `8080`},
 * `[::1]` -> {`::1`, ``}, `example.com` -> {`example.com`, ``}.
 *
 * The bracket handling is the whole reason this is a function: splitting an IPv6 literal at the
 * last colon is wrong, and an IPv6 literal is the only thing that ever makes it ambiguous.
 */
void splitHostPort(const std::string& value, std::string& host, std::string& port) {
  host = value;
  port.clear();

  if(!value.empty() && value.front() == '[') {
    auto close = value.find(']');
    if(close == std::string::npos) {
      return;                                  // malformed - compare it as it came
    }
    host = value.substr(1, close - 1);
    auto rest = value.substr(close + 1);
    if(!rest.empty() && rest.front() == ':') {
      port = rest.substr(1);
    }
    return;
  }

  auto colon = value.rfind(':');
  if(colon != std::string::npos) {
    host = value.substr(0, colon);
    port = value.substr(colon + 1);
  }
}

/** The authority of an origin - what follows `scheme://` and precedes any path. */
bool splitOrigin(const std::string& origin, std::string& scheme, std::string& authority) {
  auto separator = origin.find("://");
  if(separator == std::string::npos) {
    return false;
  }
  scheme = origin.substr(0, separator);
  auto rest = origin.substr(separator + 3);
  auto slash = rest.find('/');
  authority = slash == std::string::npos ? rest : rest.substr(0, slash);
  return true;
}

bool isHttpScheme(const std::string& scheme) {
  return scheme == "http" || scheme == "https";
}

}

AccessGuard::AccessGuard(const Config& config)
  : m_config(config)
{}

bool AccessGuard::hostMatches(const oatpp::String& host, const oatpp::String& entry) {
  if(host == nullptr || entry == nullptr) {
    return false;
  }

  std::string hostName, hostPort, entryName, entryPort;
  splitHostPort(lowered(host), hostName, hostPort);
  splitHostPort(lowered(entry), entryName, entryPort);

  if(hostName != entryName) {
    return false;
  }
  /* An entry that does not name a port accepts the host on any port. */
  return entryPort.empty() || entryPort == hostPort;
}

bool AccessGuard::originIsSelf(const oatpp::String& origin, const oatpp::String& host) {
  if(origin == nullptr || host == nullptr) {
    return false;
  }
  /*
   * Without a Host there is nothing an origin could agree with, and "agrees with nothing" is not
   * the same statement as "is allowed".
   */
  if(trimmed(lowered(host)).empty()) {
    return false;
  }

  std::string scheme, authority;
  if(!splitOrigin(trimmed(lowered(origin)), scheme, authority)) {
    return false;
  }
  if(!isHttpScheme(scheme) || authority.empty()) {
    return false;
  }

  /*
   * Deliberately an exact comparison rather than hostMatches(): a browser sends the port in the
   * origin exactly when it sends it in Host, so a difference between the two means one of them was
   * rewritten - and a rewritten Host is the DNS-rebinding case this whole check exists for.
   * Deployments that rewrite Host on purpose say so with Config::allowedOrigins.
   */
  return authority == trimmed(lowered(host));
}

AccessGuard::Decision AccessGuard::check(const oatpp::String& origin, const oatpp::String& host) const {
  Decision decision;

  auto trimmedHost = (host == nullptr) ? std::string() : trimmed(lowered(host));
  auto trimmedOrigin = (origin == nullptr) ? std::string() : trimmed(lowered(origin));

  /*------------------------------------------------------------------ Host ------------------*/

  if(!m_config.allowedHosts.empty()) {

    if(trimmedHost.empty()) {
      decision.allowed = false;
      decision.status = oatpp::web::protocol::http::Status::CODE_400;
      decision.reason = "Missing Host header";
      return decision;
    }

    bool known = false;
    for(const auto& entry : m_config.allowedHosts) {
      if(hostMatches(host, entry)) {
        known = true;
        break;
      }
    }
    if(!known) {
      decision.allowed = false;
      decision.status = oatpp::web::protocol::http::Status::CODE_403;
      decision.reason = "Host is not allowed";
      return decision;
    }
  }

  /*----------------------------------------------------------------- Origin -----------------*/

  if(m_config.checkOrigin && !trimmedOrigin.empty()) {

    /*
     * `Origin: null` is what a sandboxed frame and a `file://` page send. Neither is a place an MCP
     * client should be coming from, and accepting it would accept any of them.
     */
    if(trimmedOrigin == "null") {
      decision.allowed = false;
      decision.status = oatpp::web::protocol::http::Status::CODE_403;
      decision.reason = "Origin 'null' is not allowed";
      return decision;
    }

    bool allowed = false;

    for(const auto& entry : m_config.allowedOrigins) {
      if(entry != nullptr && trimmed(lowered(entry)) == trimmedOrigin) {
        allowed = true;
        break;
      }
    }
    if(!allowed) {
      allowed = originIsSelf(origin, host);
    }

    if(!allowed) {
      decision.allowed = false;
      decision.status = oatpp::web::protocol::http::Status::CODE_403;
      decision.reason = "Origin is not allowed";
      return decision;
    }
  }

  return decision;
}

}}}
