#ifndef oatpp_mcp_utils_HttpSanitize_hpp
#define oatpp_mcp_utils_HttpSanitize_hpp

#include "oatpp/Types.hpp"

namespace oatpp { namespace mcp { namespace utils {

/**
 * Encoding and validation of values that are about to become part of an outgoing HTTP request.
 *
 * MCP tool arguments are untrusted text, and {@link oatpp::mcp::capabilities::EndpointTool} places
 * them into positions of an HTTP request that have syntax: the request target and the header block.
 * The rule for each position is decided here, by the code that fills it, and never by the caller:
 *
 * <ul>
 *   <li>values in the request target are <b>percent-encoded</b> - encoding is lossless, the
 *       upstream receives exactly what the tool caller meant;</li>
 *   <li>header names and values are <b>validated and rejected</b> - there is no encoding for a
 *       header, and stripping the offending characters would silently change which header is being
 *       sent.</li>
 * </ul>
 *
 * Input is always treated as raw: a value that already contains <code>%20</code> is encoded to
 * <code>%2520</code>. Assuming that a caller pre-encoded a value is not sound - the only way to
 * tell the two apart is to not offer the distinction.
 *
 * Neither <code>oatpp::web::url::mapping::Pattern::reconstruct()</code> nor oatpp's HTTP serializer
 * does any of this, so this is the boundary that has to.
 */
class HttpSanitize {
public:

  /**
   * Percent-encode a value for use as one segment of a URL path.
   *
   * Reserved characters that would change the structure of the path - <code>/</code>,
   * <code>?</code>, <code>#</code> - become percent-encoded, as do the characters that terminate a
   * request line.
   * @param value - raw value, may be @c nullptr.
   * @return encoded value, or @c nullptr if @p value was @c nullptr.
   */
  static oatpp::String encodePathSegment(const oatpp::String& value);

  /**
   * Percent-encode a value for use as a query-string name or value.
   *
   * The query delimiters - <code>&amp;</code>, <code>=</code>, <code>+</code>, <code>#</code> -
   * become percent-encoded, so an argument cannot add a parameter, change one, or turn a
   * <code>+</code> into a space.
   * @param value - raw value, may be @c nullptr.
   * @return encoded value, or @c nullptr if @p value was @c nullptr.
   */
  static oatpp::String encodeQueryComponent(const oatpp::String& value);

  /**
   * Check a header name and value against RFC 9110 §5.6.
   *
   * A value containing CR, LF or NUL ends the header block early and turns the rest of the request
   * - or a whole second request - into whatever the attacker wrote.
   * @param name - header name, must be a non-empty RFC 9110 token.
   * @param value - header value, must not contain control characters.
   * @throws std::invalid_argument if either is not representable as a header. The message names the
   *         header; it never repeats the offending value.
   */
  static void validateHeaderField(const oatpp::String& name, const oatpp::String& value);

  /**
   * Final guard on the assembled request target.
   *
   * Values are encoded before they get here, so a hit means the endpoint's own path pattern is not
   * a valid request target - a programming error rather than an attack, and cheaper to catch than
   * to explain once it has been put on the wire.
   * @param target - the path (and query) that is about to be sent.
   * @throws std::invalid_argument if the target contains CR, LF or NUL.
   */
  static void validateRequestTarget(const oatpp::String& target);

};

}}}

#endif // oatpp_mcp_utils_HttpSanitize_hpp
