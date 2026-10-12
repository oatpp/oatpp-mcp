#ifndef oatpp_mcp_utils_AccessGuard_hpp
#define oatpp_mcp_utils_AccessGuard_hpp

#include "oatpp/Types.hpp"
#include "oatpp/web/protocol/http/Http.hpp"

#include <vector>

namespace oatpp { namespace mcp { namespace utils {

/**
 * Who may open, and who may address, an MCP session over HTTP.
 *
 * An MCP-over-SSE server has two endpoints and authenticates neither of them: <code>GET /sse</code>
 * opens a session and <code>POST /sessions/{id}</code> delivers a message to it. That is fine for a
 * stdio server and dangerous for one that listens on a socket, because "can reach the port" is then
 * the whole of the authorization. Two header checks remove the two attacks that do not need any
 * credential at all - see SECURITY-FINDINGS.md, finding F4:
 *
 * <ul>
 *   <li><b><code>Origin</code></b> - a page in a browser can be made to send requests to a server on
 *       the operator's own machine. If the header is present and is not this server's own origin,
 *       the request did not come from a page this server was written for. Non-browser clients -
 *       curl, the MCP SDKs, a proxy - send no <code>Origin</code> at all, so requiring one would
 *       break the common case; requiring <i>agreement</i> does not.</li>
 *   <li><b><code>Host</code></b> - DNS rebinding makes an attacker's domain resolve to
 *       <code>127.0.0.1</code>, and the browser then sends the attacker's name as the
 *       <code>Host</code> and an <code>Origin</code> that agrees with it. No comparison of the two
 *       can see this; only a list of the names this server is willing to be called by can. That
 *       list is {@link Config::allowedHosts}, and it is empty by default - see its
 *       documentation.</li>
 * </ul>
 *
 * The check is a pure function of two header values and a configuration, so that the policy can be
 * tested without a socket, and so that the endpoints cannot accidentally consult a different policy
 * from the one the tests did.
 */
class AccessGuard {
public:

  /** What the guard knows about this deployment. */
  class Config {
  public:

    /**
     * Reject a request that carries an <code>Origin</code> this server does not agree with.
     *
     * Turning this off is only sensible behind something else that enforces it, and it does not
     * have to be a proxy - a deployment whose clients are all native may prefer to enforce nothing
     * here and authenticate at the tool layer instead.
     */
    bool checkOrigin = true;

    /**
     * Origins accepted in addition to this server's own.
     *
     * Needed whenever the browser's origin is not the authority the request arrives with - a
     * reverse proxy that rewrites <code>Host</code>, a front-end on another port, a
     * <code>chrome-extension://</code> or <code>android-app://</code> client. Compared
     * case-insensitively, in full (<code>scheme://authority</code>).
     */
    std::vector<oatpp::String> allowedOrigins;

    /**
     * The names this server is willing to be addressed by, as <code>host</code> or
     * <code>host:port</code>.
     *
     * <b>Empty means "any Host is accepted"</b>, which is the only default that does not break a
     * server bound to an address the library cannot know. It also leaves DNS rebinding unmitigated,
     * so a server that listens on anything but a private, unrepudiable network should set this
     * (<code>{"localhost", "127.0.0.1"}</code> for a local one). An entry without a port matches
     * that host on any port; matching is exact, so <code>localhost</code> does not match
     * <code>localhost.evil.example</code>.
     */
    std::vector<oatpp::String> allowedHosts;

  };

  /** The outcome of one check. */
  class Decision {
  public:

    /** Whether the request may proceed. */
    bool allowed = true;

    /** What to answer when it may not; unset when it may. */
    oatpp::web::protocol::http::Status status;

    /**
     * Short, fixed description of which rule fired - for the operator's log and for the response
     * body. It never contains the offending value: the value is logged separately, rendered, and
     * the body of a refusal is not where a header gets repeated.
     */
    oatpp::String reason;

  };

public:

  AccessGuard() = default;

  explicit AccessGuard(const Config& config);

  /**
   * Apply the policy to one request.
   *
   * @param origin - the <code>Origin</code> header, @c nullptr or empty when there was none.
   * @param host - the <code>Host</code> header, @c nullptr or empty when there was none.
   * @return the decision. A default-constructed (allowed) decision is the common answer.
   */
  Decision check(const oatpp::String& origin, const oatpp::String& host) const;

  /**
   * Whether a <code>Host</code> header value is covered by one allow-list entry.
   *
   * Exposed because it is the rule an operator is most likely to get wrong, and the one most worth
   * pinning in a test.
   */
  static bool hostMatches(const oatpp::String& host, const oatpp::String& entry);

  /**
   * Whether an <code>Origin</code> header value denotes the server named by a <code>Host</code>
   * header value - the "same origin" a browser would consider this request to have.
   */
  static bool originIsSelf(const oatpp::String& origin, const oatpp::String& host);

private:
  Config m_config;

};

}}}

#endif // oatpp_mcp_utils_AccessGuard_hpp
