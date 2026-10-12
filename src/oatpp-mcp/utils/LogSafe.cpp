#include "LogSafe.hpp"

#include "oatpp/base/Log.hpp"

#include <string>
#include <utility>
#include <vector>

namespace oatpp { namespace mcp { namespace utils {

namespace {

const char* const kNull = "(null)";
const char* const kRedacted = "<redacted>";

/*
 * Field names whose value is a credential often enough that writing it to a log is a leak.
 *
 * A list of names rather than a guess about the value: "this looks like a secret" cannot be decided
 * from one string, and a wrong guess there silently removes the interesting half of a debug log.
 * A wrong guess the other way - a credential this list does not know - is why the redaction is
 * documented as best effort and not as a reason to log whatever you like.
 */
const char* const kSensitiveExact[] = {
  "auth", "key", "pwd", "secret", "token"
};

const char* const kSensitiveSubstring[] = {
  "api-key", "api_key", "apikey",
  "access-key", "access_key",
  "authorization",
  "bearer",
  "client-secret", "client_secret",
  "cookie",
  "credential",
  "passwd",
  "password",
  "private-key", "private_key",
  "secret",
  "session-token", "session_id", "sessionid",
  "token",
  "x-auth"
};

/** ASCII lower-casing. Locale-dependent casing would make the match depend on the environment. */
std::string lowered(const std::string& value) {
  std::string result;
  result.reserve(value.size());
  for(char c : value) {
    result += (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  }
  return result;
}

bool isSensitiveLowered(const std::string& name) {
  for(const char* exact : kSensitiveExact) {
    if(name == exact) {
      return true;
    }
  }
  for(const char* part : kSensitiveSubstring) {
    if(name.find(part) != std::string::npos) {
      return true;
    }
  }
  return false;
}

bool isUtf8Continuation(char c) {
  return (static_cast<v_uint8>(c) & 0xC0) == 0x80;
}

void appendEscaped(std::string& out, char c) {
  switch(c) {
    case '\r': out += "\\r"; return;
    case '\n': out += "\\n"; return;
    case '\t': out += "\\t"; return;
    default:
      break;
  }
  const v_uint8 byte = static_cast<v_uint8>(c);
  if(byte < 0x20 || byte == 0x7F) {
    static const char* const hex = "0123456789abcdef";
    out += "\\x";
    out += hex[(byte >> 4) & 0xF];
    out += hex[byte & 0xF];
  } else {
    out += c;
  }
}

/**
 * Index of the first byte of `value` that does not fit into `budget` rendered bytes.
 *
 * The budget is measured in the output, because that is what the log line has to stay inside: one
 * control character costs four bytes of it. The index is then moved back to the start of the
 * character it landed in, so a truncated value never ends in half a multi-byte character - the rest
 * of the record is not encoded, and a dangling continuation byte renders as mojibake at the end of
 * every log line that follows the cut.
 */
v_buff_size cutIndex(const std::string& value, v_buff_size budget) {
  const v_buff_size size = static_cast<v_buff_size>(value.size());
  v_buff_size rendered = 0;
  v_buff_size i = 0;

  for(; i < size; i++) {
    if(rendered >= budget) {
      break;
    }
    const v_uint8 c = static_cast<v_uint8>(value[i]);
    rendered += (c == '\r' || c == '\n' || c == '\t') ? 2
                : ((c < 0x20 || c == 0x7F) ? 4 : 1);
  }

  while(i > 0 && i < size && isUtf8Continuation(value[i])) {
    i --;
  }

  return i;
}

std::string render(const std::string& value, v_buff_size cut) {
  std::string out;
  out.reserve(static_cast<size_t>(cut) + 16);
  for(v_buff_size i = 0; i < cut; i++) {
    appendEscaped(out, value[i]);
  }
  return out;
}

std::string renderTruncated(const std::string& value, v_buff_size maxLength) {
  if(maxLength <= 0) {
    maxLength = 1;
  }
  const v_buff_size size = static_cast<v_buff_size>(value.size());
  const v_buff_size cut = cutIndex(value, maxLength);
  std::string out = render(value, cut);
  if(cut < size) {
    out += "...[+" + std::to_string(size - cut) + " bytes]";
  }
  return out;
}

void splitQuery(const std::string& query, std::vector<std::string>& parts) {
  std::string::size_type start = 0;
  while(true) {
    const std::string::size_type amp = query.find('&', start);
    if(amp == std::string::npos) {
      parts.push_back(query.substr(start));
      return;
    }
    parts.push_back(query.substr(start, amp - start));
    start = amp + 1;
  }
}

}

oatpp::String LogSafe::text(const oatpp::String& value, v_buff_size maxLength) {
  if(value == nullptr) {
    return oatpp::String(kNull);
  }
  return oatpp::String(renderTruncated(*value, maxLength));
}

oatpp::String LogSafe::text(const char* value, v_buff_size maxLength) {
  if(value == nullptr) {
    return oatpp::String(kNull);
  }
  return oatpp::String(renderTruncated(std::string(value), maxLength));
}

bool LogSafe::isSensitiveName(const oatpp::String& name) {
  if(name == nullptr || name->empty()) {
    return false;
  }
  return isSensitiveLowered(lowered(*name));
}

oatpp::String LogSafe::headerValue(const oatpp::String& name,
                                   const oatpp::String& value,
                                   v_buff_size maxLength)
{
  if(isSensitiveName(name)) {
    return oatpp::String(kRedacted);
  }
  return text(value, maxLength);
}

oatpp::String LogSafe::requestTarget(const oatpp::String& target, v_buff_size maxLength) {

  if(target == nullptr) {
    return oatpp::String(kNull);
  }

  const std::string& raw = *target;
  const std::string::size_type question = raw.find('?');

  if(question == std::string::npos) {
    return text(target, maxLength);
  }

  std::string out = raw.substr(0, question + 1);
  std::vector<std::string> parts;
  splitQuery(raw.substr(question + 1), parts);

  for(size_t i = 0; i < parts.size(); i++) {
    if(i != 0) {
      out += '&';
    }
    const std::string& part = parts[i];
    const std::string::size_type equals = part.find('=');
    if(equals != std::string::npos && isSensitiveLowered(lowered(part.substr(0, equals)))) {
      // the name stays - it is what tells you which credential was being sent - the value does not
      out += part.substr(0, equals) + "=" + kRedacted;
    } else {
      out += part;
    }
  }

  return text(oatpp::String(std::move(out)), maxLength);
}

void LogSafe::logRequest(const char* tag,
                         const oatpp::String& endpointName,
                         const oatpp::String& method,
                         const oatpp::String& pathPattern,
                         const oatpp::String& target,
                         const oatpp::web::protocol::http::Headers& headers,
                         const oatpp::String& body)
{
  /*
   * Which tool ran is an operator's question and stays at info - through a proxy that blocks tools
   * it is also a security question, and the answer must survive a default log level. What the
   * caller sent is nobody's business at that level, and it is the part that is not ours.
   */
  OATPP_LOGi(tag, "tool '{}': {} {}", text(endpointName), text(method), text(pathPattern))

  OATPP_LOGd(tag, "request target: '{}'", requestTarget(target))

  for(auto& h : headers.getAll()) {
    const oatpp::String name = h.first.toString();
    OATPP_LOGd(tag, "header: {}: '{}'", text(name), headerValue(name, h.second.toString()))
  }

  if(body != nullptr) {
    OATPP_LOGd(tag, "body: '{}'", text(body, MaxMessageLength))
  }
}

}}}
