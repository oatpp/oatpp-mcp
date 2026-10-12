#ifndef oatpp_mcp_utils_LogSafe_hpp
#define oatpp_mcp_utils_LogSafe_hpp

#include "oatpp/Types.hpp"
#include "oatpp/web/protocol/http/Http.hpp"

namespace oatpp { namespace mcp { namespace utils {

/**
 * Rendering of untrusted text so that it cannot forge a log line, and so that a log does not become
 * a second place secrets are stored.
 *
 * Logs are a line-oriented sink that is usually read - and often aggregated - by somebody who never
 * saw the request. Two properties are worth keeping for it:
 *
 * <ul>
 *   <li><b>one log record per input line.</b> A {@code '\n'} in a tool argument, in a message body
 *       or in an exception text otherwise writes the attacker's own line into the operator's log,
 *       with this server's timestamp and tag prefixed to it - which is indistinguishable from a
 *       real one. Control characters therefore become visible escapes instead of characters.</li>
 *   <li><b>a bounded record.</b> A tool argument can be megabytes long; the log should not be.</li>
 * </ul>
 *
 * Values that name a credential are replaced rather than escaped: an escaped password is still a
 * password. Redaction is best effort - it recognises the common names, it cannot know this
 * deployment's - and it is not a security boundary, only a reason not to be nervous about turning
 * debug logging on.
 *
 * Nothing here changes what is <i>sent</i>; {@link HttpSanitize} is what decides that.
 */
class LogSafe {
public:

  /**
   * Budget for a single value - a request target, a header value, an exception text. Chosen to be
   * comfortably below the 4 KiB buffer oatpp's default logger formats into, so that the whole
   * record survives rather than the interesting part of it.
   */
  static constexpr v_buff_size MaxValueLength = 1024;

  /** Budget for a whole message - an inbound JSON-RPC message or a request body. */
  static constexpr v_buff_size MaxMessageLength = 2048;

public:

  /**
   * Escape control characters and bound the length of a value.
   *
   * {@code '\r'}, {@code '\n'} and {@code '\t'} become the two-character sequences
   * <code>\\r</code>, <code>\\n</code>, <code>\\t</code>; every other C0 control and DEL becomes
   * <code>\\xNN</code>. Bytes >= 0x80 are left alone - they are most likely UTF-8, and escaping
   * them would make a message in any other script unreadable.
   *
   * At most {@link MaxValueLength} bytes of the result are produced (one escape may overshoot the
   * budget by up to three bytes), and what was dropped is reported rather than hidden:
   * <code>...[+1234 bytes]</code>. The cut never splits a UTF-8 sequence.
   *
   * @param value - text to render, may be @c nullptr.
   * @param maxLength - budget for the rendered text.
   * @return the rendered text; never @c nullptr - a null input renders as <code>(null)</code>.
   */
  static oatpp::String text(const oatpp::String& value, v_buff_size maxLength = MaxValueLength);

  /**
   * As {@link text(const oatpp::String&, v_buff_size)}, for a C string - typically
   * <code>std::exception::what()</code>, which is text from a library this one does not control.
   */
  static oatpp::String text(const char* value, v_buff_size maxLength = MaxValueLength);

  /**
   * Whether a field name suggests that its value is a credential.
   *
   * Matched case-insensitively, as an exact name (<code>key</code>) or as a substring
   * (<code>x-api-key</code>, <code>Authorization</code>).
   */
  static bool isSensitiveName(const oatpp::String& name);

  /**
   * Render a header value: {@link text()} for everything, <code>&lt;redacted&gt;</code> for the
   * names that hold credentials.
   * @param name - header name, decides whether the value survives.
   * @param value - header value, may be @c nullptr.
   */
  static oatpp::String headerValue(const oatpp::String& name,
                                   const oatpp::String& value,
                                   v_buff_size maxLength = MaxValueLength);

  /**
   * Render a request target: values of sensitive query parameters are replaced first, then the
   * whole thing is escaped and truncated.
   *
   * The parameter <i>names</i> are what is matched, so <code>?api_key=…</code> and
   * <code>?X-Auth-Token=…</code> are both redacted while <code>?userId=42</code> stays readable.
   * A parameter with no value at all has nothing to redact and is left as it is.
   */
  static oatpp::String requestTarget(const oatpp::String& target,
                                     v_buff_size maxLength = MaxValueLength);

  /**
   * Log one outgoing tool request.
   *
   * The split between the two priorities is the point, and it is why this is a function rather than
   * three log statements at the call site:
   *
   * <ul>
   *   <li><b>info</b> - one line naming the endpoint, its method and its <i>path pattern</i>. That
   *       is everything an operator needs to see which tool ran - the question a proxy that blocks
   *       tools turns into a security question - and none of it is caller-supplied;</li>
   *   <li><b>debug</b> - the resolved target, the headers and the body: attacker-shaped, useful
   *       only when something is wrong, and therefore off unless somebody asks for it.</li>
   * </ul>
   *
   * Every value that reaches a log statement goes through this class, including the
   * developer-supplied ones: the invariant "nothing unrendered reaches the log" is worth more than
   * the four calls it costs to hold.
   *
   * @param tag - log tag, so that the records keep naming the place they came from.
   * @param endpointName - name of the endpoint being called.
   * @param method - HTTP method.
   * @param pathPattern - the endpoint's path pattern, e.g. <code>/users/{userId}</code> - not the
   *        resolved path, which is logged at debug.
   * @param target - the resolved request target.
   * @param headers - the headers about to be sent.
   * @param body - serialized body, or @c nullptr when there is none.
   */
  static void logRequest(const char* tag,
                         const oatpp::String& endpointName,
                         const oatpp::String& method,
                         const oatpp::String& pathPattern,
                         const oatpp::String& target,
                         const oatpp::web::protocol::http::Headers& headers,
                         const oatpp::String& body);

};

}}}

#endif // oatpp_mcp_utils_LogSafe_hpp
