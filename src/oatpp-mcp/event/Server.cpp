//
// Created by Leonid S on 12/8/24.
//

#include "Server.hpp"

#include "oatpp/base/Log.hpp"

#include <thread>
#include <vector>

namespace oatpp { namespace mcp { namespace event {

/*
 * Three constructors rather than default arguments: `Config()` as a default argument of a
 * constructor of the class that <i>contains</i> Config is not usable yet at that point in the class
 * definition, because Config's own default member initializers are not complete.
 */

Server::Server()
  : Server(nullptr, Config())
{}

Server::Server(const std::shared_ptr<Session::Pinger>& pinger)
  : Server(pinger, Config())
{}

Server::Server(const std::shared_ptr<Session::Pinger>& pinger, const Config& config)
  : m_pinger(pinger)
  , m_config(config)
{}

std::shared_ptr<Session> Server::startNewSession(const std::shared_ptr<Session::EventListener>& listener) {

  std::shared_ptr<Session> session;

  {
    std::lock_guard<std::mutex> lock(m_mutex);

    /*
     * Checked before the session exists: the cost being bounded is a thread and a registry entry,
     * and refusing to create them is the whole point. Returning nullptr rather than throwing keeps
     * the decision with the caller, which is the only place that knows what a full server should
     * answer. See SECURITY-FINDINGS.md, finding F4.
     */
    if(m_config.maxSessions > 0 && m_sessions.size() >= m_config.maxSessions) {
      OATPP_LOGw("[oatpp::mcp::event::Server::startNewSession()]",
                 "Warning - session limit of {} reached, refusing a new session",
                 m_config.maxSessions)
      return nullptr;
    }

    session = std::make_shared<Session>(
      m_pinger,
      std::chrono::milliseconds(m_config.sessionIdleTimeoutMillis),
      m_config.maxQueuedEvents);

    if(m_sessions.find(session->getId()) != m_sessions.end()) {
      /* Identifiers are random 122-bit values, so this is not a race to be handled - it is the
       * identifier generator having stopped being random, which is finding F2 and must not be
       * papered over by quietly overwriting the session that got there first. */
      OATPP_LOGe("[oatpp::mcp::Server::startNewSession()]",
                 "Error - session identifier collision, identifiers are not unique: {}",
                 session->getId())
    }
    m_sessions[session->getId()] = session;
  }

  OATPP_LOGd("[oatpp::mcp::Server::startNewSession()]", "New session started {}", session->getId())

  std::thread t([this, session, listener]{
    session->listen(listener);
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      auto it = m_sessions.find(session->getId());
      /* Only remove our own entry: if an identifier were ever shared, the first session to finish
       * must not retire the session that replaced it. */
      if(it != m_sessions.end() && it->second == session) {
        m_sessions.erase(it);
      }
      OATPP_LOGd("Server", "sessions count={}", m_sessions.size())
    }
  });

  t.detach();

  return session;
}

std::shared_ptr<Session> Server::getSession(const oatpp::String& sessionId) const {
  std::lock_guard<std::mutex> lock(m_mutex);
  auto it = m_sessions.find(sessionId);
  if(it != m_sessions.end()) {
    return it->second;
  }
  return nullptr;
}

v_uint64 Server::sessionCount() const {
  std::lock_guard<std::mutex> lock(m_mutex);
  return static_cast<v_uint64>(m_sessions.size());
}

void Server::closeSessions() {
  std::vector<std::shared_ptr<Session>> sessions;
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    sessions.reserve(m_sessions.size());
    for(const auto& entry : m_sessions) {
      sessions.push_back(entry.second);
    }
  }
  /* Closed outside the lock: a session's own teardown takes the server's lock to unregister, and
   * holding it across close() would put the two locks in the same cycle. */
  for(const auto& session : sessions) {
    session->close();
  }
}

}}}
