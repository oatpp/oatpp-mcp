#include "HttpSanitize.hpp"

#include "oatpp/encoding/Url.hpp"

#include <stdexcept>

namespace oatpp { namespace mcp { namespace utils {

namespace {

/*
 * The characters that keep their meaning inside a single path segment or query component: the
 * RFC 3986 unreserved set - which is exactly what oatpp::encoding::Url::Config allows by
 * default - plus the sub-delimiters no parser treats as structural in that position.
 *
 * Deliberately encoded: '/', '?', '#', '%', '&', '=', '+', ':', ';' - and every control character,
 * which is what terminates a request line or a header block. Encoding the rest is harmless: the
 * upstream decodes them back.
 */
const oatpp::encoding::Url::Config& componentConfig() {
  static const oatpp::encoding::Url::Config config = []{
    oatpp::encoding::Url::Config c;
    c.allowChar('!');
    c.allowChar('\'');
    c.allowChar('(');
    c.allowChar(')');
    c.allowChar('*');
    return c;
  }();
  return config;
}

/**
 * RFC 9110 §5.6: a field-value is VCHAR, SP and obs-text. CR, LF and NUL are what end a header
 * block, and the remaining C0 controls and DEL have no meaning that survives serialization.
 */
bool isHeaderValueChar(v_uint8 c) {
  return (c >= 0x20 && c <= 0x7E) || c >= 0x80;
}

/** RFC 9110 §5.6.2: tchar. */
bool isFieldNameChar(v_uint8 c) {
  switch(c) {
    case '!': case '#': case '$': case '%': case '&': case '\'':
    case '*': case '+': case '-': case '.': case '^': case '_':
    case '`': case '|': case '~':
      return true;
    default:
      return (c >= '0' && c <= '9')
          || (c >= 'a' && c <= 'z')
          || (c >= 'A' && c <= 'Z');
  }
}

[[noreturn]] void rejectFieldName(const oatpp::String& name) {
  throw std::invalid_argument(
    "[oatpp::mcp::utils::HttpSanitize::validateHeaderField()]: Error - '" +
    std::string(name->c_str()) + "' is not a valid HTTP header name"
  );
}

}

oatpp::String HttpSanitize::encodePathSegment(const oatpp::String& value) {
  return oatpp::encoding::Url::encode(value, componentConfig());
}

oatpp::String HttpSanitize::encodeQueryComponent(const oatpp::String& value) {
  return oatpp::encoding::Url::encode(value, componentConfig());
}

void HttpSanitize::validateHeaderField(const oatpp::String& name, const oatpp::String& value) {

  if(name == nullptr || name->empty()) {
    throw std::invalid_argument(
      "[oatpp::mcp::utils::HttpSanitize::validateHeaderField()]: Error - header name is empty");
  }

  for(char c : *name) {
    if(!isFieldNameChar(static_cast<v_uint8>(c))) {
      rejectFieldName(name);
    }
  }

  if(value == nullptr) {
    return; // no value at all is not an invalid one
  }

  for(char c : *value) {
    if(!isHeaderValueChar(static_cast<v_uint8>(c))) {
      // The value is deliberately not repeated: it is the thing being rejected, and it may
      // contain the very characters that make it unacceptable.
      throw std::invalid_argument(
        "[oatpp::mcp::utils::HttpSanitize::validateHeaderField()]: Error - value of header '" +
        std::string(name->c_str()) + "' contains a character that cannot be sent in a HTTP header"
      );
    }
  }
}

void HttpSanitize::validateRequestTarget(const oatpp::String& target) {

  if(target == nullptr) {
    return;
  }

  for(char c : *target) {
    if(c == '\r' || c == '\n' || c == '\0') {
      throw std::invalid_argument(
        "[oatpp::mcp::utils::HttpSanitize::validateRequestTarget()]: Error - request target "
        "contains a control character and cannot be sent"
      );
    }
  }
}

}}}
