//
// Created by Leonid S on 12/8/24.
//

#ifndef OATPP_MCP_EVENT_EVENTSTREAM_HPP
#define OATPP_MCP_EVENT_EVENTSTREAM_HPP

#include "oatpp/Types.hpp"

#include <mutex>
#include <condition_variable>
#include <list>
#include <chrono>

namespace oatpp { namespace mcp { namespace event {

struct Event {

  oatpp::String name;
  oatpp::String data;

  explicit inline operator bool() const {
    return name != nullptr && data != nullptr;
  }

};

/**
 * What became of an event that was handed to an {@link EventOutputStream}.
 *
 * <b>Why this is a result and not <code>void</code>.</b> A queue has to be finite - an unbounded one
 * turns a client that stopped reading into an out-of-memory condition - and a finite queue that
 * refuses work has to say so. Until now it did not: <code>post()</code> returned nothing, so a
 * dropped RPC response was indistinguishable from a delivered one, at every layer above, including
 * the HTTP status code the caller got for its <code>POST</code>. See SECURITY-FINDINGS.md, F8.
 */
enum class PostResult {

  /** The event is in the queue and will be read by whoever owns the stream. */
  Queued,

  /**
   * The queue is at its limit and the event was discarded.
   *
   * The reader is alive but behind - or has stopped reading without closing. Retrying later may
   * succeed, which is what distinguishes this from {@link DroppedClosed}.
   */
  DroppedFull,

  /**
   * The stream is closed and the event was discarded.
   *
   * Nothing will ever read it; retrying cannot help.
   */
  DroppedClosed

};

/** Whether the event was accepted. */
inline bool isQueued(PostResult result) {
  return result == PostResult::Queued;
}

/**
 * The reason as a short, fixed string - for logs and for test failures.
 * Not localised, not caller-supplied: it is safe to put in a log record as it stands.
 */
const char* describe(PostResult result);

/**
 * What a stream did with the events it was handed.
 *
 * A counter and not a log, because the two have different lifetimes: a log line is a fact that
 * happened once, a counter is the property an operator wants to alert on.
 */
struct StreamStats {

  /** Events accepted into the queue. */
  v_uint64 queued = 0;

  /** Events refused because the queue was at {@link EventStream::maxQueueSize()}. */
  v_uint64 droppedFull = 0;

  /** Events refused because the stream was closed. */
  v_uint64 droppedClosed = 0;

  /** Events refused for any reason. */
  v_uint64 dropped() const {
    return droppedFull + droppedClosed;
  }

};

class EventInputStream {
public:
  virtual ~EventInputStream() = default;
  virtual Event read(const std::chrono::duration<v_int64, std::milli>& timeout) = 0;
};

class EventOutputStream {
public:
  virtual ~EventOutputStream() = default;

  /**
   * Hand an event to the stream.
   * @return whether it was queued - see {@link PostResult}. Never @c void: a caller that cannot tell
   *         a drop from a delivery cannot report one.
   */
  virtual PostResult post(const Event& event) = 0;
};

/**
 * A bounded, thread-safe queue of {@link Event}s - the pipe between an MCP session and whoever is
 * serving it.
 *
 * Two properties are deliberate and are the whole reason this class has the interface it has:
 *
 * <ul>
 *   <li><b>{@link post()} never blocks.</b> The producer is a session thread or an HTTP connection
 *       thread; making it wait for a reader that may have died converts a lost message into a hung
 *       server. It refuses instead, and says so.</li>
 *   <li><b>the queue is bounded, and a refusal is reported.</b> {@link maxQueueSize()} is the memory
 *       bound; {@link PostResult} and {@link stats()} are the diagnosis. Events already queued when
 *       the stream is closed are <i>not</i> discarded - they are read first, then the reader sees
 *       end-of-stream - because a session that is being torn down may still be holding its client's
 *       last answers.</li>
 * </ul>
 */
class EventStream : public EventInputStream, public EventOutputStream {
public:

  /**
   * Default queue depth, per stream.
   *
   * A session has two of these (in and out). One hundred queued messages is far more than a working
   * client accumulates, so reaching it means a reader has stalled rather than that the server is
   * busy - and it is small enough that a stalled reader costs a bounded amount of memory.
   */
  static constexpr v_uint32 DefaultMaxQueueSize = 100;

  /**
   * Log the first drop, then every this-many-<i>th</i> drop of the same stream.
   *
   * A stream whose reader has died drops forever; one record per drop would trade a lost message for
   * a log flood, which is the same availability problem one level down. The running total is in
   * every record, so a sampled line still says how much was lost.
   */
  static constexpr v_uint64 DropLogInterval = 100;

private:
  const v_uint32 m_maxQueueSize;
private:
  std::list<Event> m_queue;
  mutable std::mutex m_mutex;
  std::condition_variable m_cv;
private:
  bool m_open;
  StreamStats m_stats;
public:

  /**
   * @param maxQueueSize - most events to hold at once. <code>0</code> means no limit, which is an
   *        argument for a stream whose producer is the only thing that can make it grow (a stdio
   *        session, say) and an out-of-memory bug otherwise.
   */
  explicit EventStream(v_uint32 maxQueueSize = DefaultMaxQueueSize);

  /**
   * Queue an event. Never blocks, never throws for a full queue - it refuses.
   */
  PostResult post(const Event& event) override;

  /**
   * Take the oldest event.
   * @param timeout - how long to wait for one; <code>0</code> waits until there is something to read
   *        or the stream closes.
   * @return the event, or an invalid one (see {@link Event::operator bool}) on timeout and once the
   *         stream is closed <i>and drained</i>.
   */
  Event read(const std::chrono::duration<v_int64, std::milli>& timeout = std::chrono::milliseconds(0)) override;

  /**
   * Close the stream and wake every reader.
   *
   * Queued events survive: a reader that comes back for them gets them, and end-of-stream after
   * that. What is not delivered is reported by {@link stats()} at the moment it was refused, not
   * here.
   */
  void close();

  bool isOpen();

  /** The limit this stream was constructed with; <code>0</code> means unbounded. */
  v_uint32 maxQueueSize() const;

  /** Counters for this stream. */
  StreamStats stats() const;

};

}}}

#endif //OATPP_MCP_EVENT_EVENTSTREAM_HPP
