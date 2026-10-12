//
// Created by Leonid S on 12/8/24.
//

#ifndef OATPP_MCP_EVENT_SESSION_HPP
#define OATPP_MCP_EVENT_SESSION_HPP

#include "EventStream.hpp"

#include <chrono>
#include <memory>

namespace oatpp { namespace mcp { namespace event {

class Session {
public:

  class Pinger {
  public:
    virtual ~Pinger() = default;
    virtual void onPing(Session& session) = 0;
  };

public:

  class EventListener {
  public:
    virtual ~EventListener() = default;
    virtual void onEvent(Session& session, const Event& event) = 0;
  };

public:

  class AssociatedData {
  public:
    virtual ~AssociatedData() = default;
  };

private:
  void closeNonBlocking();
private:
  /**
   * Random identifier, generated once per session. Never derived from the object, its address, a
   * counter or a timestamp - see oatpp::mcp::utils::Uuid and SECURITY-FINDINGS.md (F2).
   */
  oatpp::String m_id;
  /**
   * How long a session may go without an inbound message before it is closed. Zero - the default -
   * never expires. See SECURITY-FINDINGS.md, findings F4 and F5.
   */
  std::chrono::milliseconds m_idleTimeout;
private:
  std::shared_ptr<Pinger> m_pinger;
  std::shared_ptr<EventStream> m_inStream;
  std::shared_ptr<EventStream> m_outStream;
private:
  bool m_open;
  std::mutex m_mutex;
private:
  std::shared_ptr<AssociatedData> m_data;
public:

  /**
   * @param pinger - optional heartbeat, invoked when no message arrived for one ping interval.
   * @param idleTimeout - close the session once no <b>inbound</b> message arrived for this long.
   *        Zero never expires. Outbound traffic does not count: a client that is only receiving is
   *        by definition not the client that forgot to hang up.
   * @param maxQueuedEvents - depth of each of the two queues, in and out. Zero means unbounded,
   *        which is a memory bound being removed, not a limit being set - see
   *        {@link EventStream::EventStream()}. A refusal to queue is reported to whoever posted it
   *        rather than blocking the poster: see SECURITY-FINDINGS.md, finding F8.
   */
  Session(const std::shared_ptr<Pinger>& pinger = nullptr,
          std::chrono::milliseconds idleTimeout = std::chrono::milliseconds::zero(),
          v_uint32 maxQueuedEvents = EventStream::DefaultMaxQueueSize);

  ~Session();

  /** Messages on their way <i>to</i> the session's listener. */
  std::shared_ptr<EventStream> getInStream();

  /** Messages on their way from the session back to the client. */
  std::shared_ptr<EventStream> getOutStream();

  /**
   * Associate any arbitrary data with session
   * @param data
   */
  void setAssociatedData(const std::shared_ptr<AssociatedData>& data);

  /**
   * Get session associated data
   * @return
   */
  std::shared_ptr<AssociatedData> getAssociatedData() const;

  /**
   * process session
   */
  void listen(std::shared_ptr<EventListener> listener);

  bool isOpen();

  void close();

  /**
   * The session identifier - a random version-4 UUID, stable for the lifetime of the session.
   *
   * This value is what clients address in <code>POST /sessions/{sessionId}</code>, and the SSE
   * endpoints authenticate nothing (SECURITY-FINDINGS.md, F4), so it is the only thing standing
   * between one client and another client's message stream. It must be unguessable, and it must
   * not be derivable from anything the server otherwise reveals.
   * @return 36 characters, canonical UUID form.
   */
  oatpp::String getId() const;

};

}}}

#endif //OATPP_MCP_EVENT_SESSION_HPP
