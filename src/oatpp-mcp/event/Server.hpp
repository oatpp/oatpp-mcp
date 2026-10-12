//
// Created by Leonid S on 12/8/24.
//

#ifndef OATPP_MCP_EVENT_SERVER_HPP
#define OATPP_MCP_EVENT_SERVER_HPP

#include "Session.hpp"

#include <unordered_map>
#include <mutex>

namespace oatpp { namespace mcp { namespace event {

class Server {
public:

  /**
   * Limits on the session registry.
   *
   * Every session costs a thread of its own, and the SSE connection that opened it holds a second
   * one for as long as it lives - see SECURITY-FINDINGS.md, finding F5. Nothing else in the
   * embedding application bounds how many sessions a client can ask for, so the bound lives here.
   */
  struct Config {

    /**
     * Most sessions to keep at once; <code>0</code> means no limit.
     *
     * The default is deliberately generous - a thousand concurrent SSE clients is far past what an
     * MCP server is likely to see - because the point is that the number is <i>finite</i>: an
     * unbounded one is a memory and thread-exhaustion bug waiting for one client that does not close
     * its connections.
     */
    v_uint64 maxSessions = 1000;

    /**
     * Close a session once no inbound message arrived for this many milliseconds; <code>0</code>
     * never expires.
     *
     * Off by default: expiring a client that is connected but quiet is a behaviour change, and a
     * stdio session in particular is expected to sit idle between tool calls. Set it where sessions
     * are cheap and short-lived, or where a lingering session is worth more than a lingering client.
     */
    v_int64 sessionIdleTimeoutMillis = 0;

    /**
     * Most events to queue per session and per direction (inbound messages, outbound replies);
     * <code>0</code> means no limit.
     *
     * This is the memory bound of an idle or a stalled client: every queued event is a whole message
     * held for somebody who is not reading it. Refusing is loud - the poster is told, the stream
     * counts it, and <code>POST /sessions/{id}</code> answers 503 rather than pretending to have
     * accepted the message - see SECURITY-FINDINGS.md, finding F8.
     *
     * Raise it for a client that legitimately pipelines a great many calls while it is not reading
     * its own event stream; leave it alone otherwise, and treat a nonzero drop counter as a client
     * or a proxy to go and look at.
     */
    v_uint32 maxQueuedEvents = EventStream::DefaultMaxQueueSize;

  };

private:
  std::shared_ptr<Session::Pinger> m_pinger;
  Config m_config;
private:
  std::unordered_map<oatpp::String, std::shared_ptr<Session>> m_sessions;
private:
  mutable std::mutex m_mutex;
public:

  /** No heartbeat, default limits. */
  Server();

  /** The given heartbeat, default limits. */
  explicit Server(const std::shared_ptr<Session::Pinger>& pinger);

  Server(const std::shared_ptr<Session::Pinger>& pinger, const Config& config);

  /**
   * Register a session and start listening to it.
   *
   * @return the session, or @c nullptr when {@link Config::maxSessions} has been reached - a caller
   *         that answers over HTTP should reply 503 rather than dereferencing it.
   */
  std::shared_ptr<Session> startNewSession(const std::shared_ptr<Session::EventListener>& listener);

  std::shared_ptr<Session> getSession(const oatpp::String& sessionId) const;

  /** How many sessions are registered right now. */
  v_uint64 sessionCount() const;

  /**
   * Close every registered session.
   *
   * Each session removes itself from the registry as its thread finishes, so this is a request to
   * shut down and not a guarantee that the count is zero on return.
   */
  void closeSessions();

};

}}}

#endif //OATPP_MCP_EVENT_SERVER_HPP
