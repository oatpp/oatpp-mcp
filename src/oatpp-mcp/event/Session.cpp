//
// Created by Leonid S on 12/8/24.
//

#include "Session.hpp"
#include "oatpp-mcp/utils/Uuid.hpp"
#include "oatpp/base/Log.hpp"

namespace oatpp { namespace mcp { namespace event {

namespace {

/** How long a session waits for a message before it asks the client whether it is still there. */
constexpr std::chrono::milliseconds kPingInterval{5000};

/** Floor for a wait, so that a very short idle timeout does not turn the loop into a spin. */
constexpr std::chrono::milliseconds kMinWait{10};

}

Session::Session(const std::shared_ptr<Pinger>& pinger,
                 std::chrono::milliseconds idleTimeout,
                 v_uint32 maxQueuedEvents)
  : m_id(utils::Uuid::generateV4())
  , m_idleTimeout(idleTimeout)
  , m_pinger(pinger)
  , m_inStream(std::make_shared<EventStream>(maxQueuedEvents))
  , m_outStream(std::make_shared<EventStream>(maxQueuedEvents))
  , m_open(true)
{}

Session::~Session() {
  OATPP_LOGd("[oatpp::mcp::event::Session::~Session()]", "Closing session")
  close();
}

std::shared_ptr<EventStream> Session::getInStream() {
  return m_inStream;
}

std::shared_ptr<EventStream> Session::getOutStream() {
  return m_outStream;
}

void Session::setAssociatedData(const std::shared_ptr<AssociatedData>& data) {
  m_data = data;
}

std::shared_ptr<Session::AssociatedData> Session::getAssociatedData() const {
  return m_data;
}

void Session::listen(std::shared_ptr<EventListener> listener) {

  if(!listener) {
    OATPP_LOGe("[oatpp::mcp::Session::listen()]", "Error - listener should NOT be null")
    return;
  }

  /*
   * Both are touched only by the thread running this loop, so neither needs the mutex. "Activity"
   * is an inbound message: a client that is happily receiving results is not a client that forgot
   * to hang up.
   */
  auto lastActivity = std::chrono::steady_clock::now();
  auto lastPing = lastActivity;

  while (isOpen()) {

    /*
     * This is the body of a detached thread, and an exception escaping it is std::terminate for the
     * whole process - and, short of that, the session would never be removed from its server's
     * registry. A listener is extension code, so "it cannot throw" is not a property of this
     * library. Log, drop the message, keep the session: one bad event is not a reason to hang up on
     * a client. See SECURITY-FINDINGS.md, finding F3.
     */
    try {

      /*
       * Wake up for the idle timeout even when it is shorter than the ping interval - otherwise an
       * expiring session lives up to one ping interval past its expiry.
       */
      auto wait = kPingInterval;
      if(m_idleTimeout > std::chrono::milliseconds::zero()) {
        auto since = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - lastActivity);
        auto remaining = m_idleTimeout - since;
        if(remaining < wait) {
          wait = remaining < kMinWait ? kMinWait : remaining;
        }
      }

      auto event = m_inStream->read(wait);
      auto now = std::chrono::steady_clock::now();

      if(event) {
        lastActivity = now;
        listener->onEvent(*this, event);
      } else if (m_pinger && (now - lastPing) >= kPingInterval) {
        lastPing = now;
        m_pinger->onPing(*this);
      }

      if(m_idleTimeout > std::chrono::milliseconds::zero()
         && (now - lastActivity) >= m_idleTimeout) {
        /*
         * The client stopped talking. Closing the session also unblocks the SSE writer that is
         * parked on the outbound stream, which is what ends the response and frees the connection
         * thread - see SECURITY-FINDINGS.md, findings F4 and F5.
         */
        OATPP_LOGi("[oatpp::mcp::Session::listen()]",
                   "Session {} idle for {}ms - closing", m_id, m_idleTimeout.count())
        close();
        break;
      }

    } catch (const std::exception& e) {
      OATPP_LOGe("[oatpp::mcp::Session::listen()]",
                 "Error - listener threw for session {}, continuing: {}", m_id, e.what())
    } catch (...) {
      OATPP_LOGe("[oatpp::mcp::Session::listen()]",
                 "Error - listener threw an unknown exception for session {}, continuing", m_id)
    }

  }

}

bool Session::isOpen() {
  std::lock_guard<std::mutex> lock(m_mutex);
  if(!m_inStream->isOpen()) {
    closeNonBlocking();
  }
  return m_open;
}

void Session::closeNonBlocking() {
  m_open = false;
  m_inStream->close();
  m_outStream->close();
}

void Session::close() {
  std::lock_guard<std::mutex> lock(m_mutex);
  closeNonBlocking();
}

oatpp::String Session::getId() const {
  return m_id;
}

}}}
