//
// Created by Leonid S on 12/8/24.
//

#include "EventStream.hpp"

#include "oatpp-mcp/utils/LogSafe.hpp"

#include "oatpp/base/Log.hpp"

namespace oatpp { namespace mcp { namespace event {

const char* describe(PostResult result) {
  switch(result) {
    case PostResult::Queued: return "queued";
    case PostResult::DroppedFull: return "queue full";
    case PostResult::DroppedClosed: return "stream closed";
  }
  return "unknown";
}

EventStream::EventStream(v_uint32 maxQueueSize)
  : m_maxQueueSize(maxQueueSize)
  , m_open(true)
{}

PostResult EventStream::post(const Event& event) {

  PostResult result;
  StreamStats stats;

  {
    std::lock_guard<std::mutex> lock(m_mutex);

    if(!m_open) {
      m_stats.droppedClosed ++;
      result = PostResult::DroppedClosed;
    } else if(m_maxQueueSize > 0 && m_queue.size() >= m_maxQueueSize) {
      m_stats.droppedFull ++;
      result = PostResult::DroppedFull;
    } else {
      m_queue.push_back(event);
      m_stats.queued ++;
      result = PostResult::Queued;
    }

    stats = m_stats;
  }

  if(result == PostResult::Queued) {
    m_cv.notify_one();
    return result;
  }

  /*
   * Logged outside the lock: a log handler is somebody else's code, and one that formats slowly -
   * or that touches this stream - must not run while the queue is held.
   *
   * Rate-limited, and the totals travel with the line, so that sampling loses the repetition and
   * not the size of the problem. Nothing about the event itself is printed beyond its name: the
   * data is whatever the tool produced, and a drop is a transport fact, not a content one.
   */
  auto dropped = stats.dropped();
  if(dropped == 1 || dropped % DropLogInterval == 0) {
    OATPP_LOGw("[oatpp::mcp::event::EventStream::post()]",
               "Warning - event '{}' not queued ({}); limit={}, queued={}, dropped={}",
               oatpp::mcp::utils::LogSafe::text(event.name),
               describe(result),
               m_maxQueueSize,
               stats.queued,
               dropped)
  }

  return result;

}

Event EventStream::read(const std::chrono::duration<v_int64, std::milli>& timeout) {

  Event result;

  std::unique_lock<std::mutex> lock(m_mutex);

  if(timeout.count() == 0) {
    while (m_queue.empty() && m_open) {
      m_cv.wait(lock);
    }
  } else {
    auto now = std::chrono::system_clock::now();
    auto waitUntil = now + timeout;
    while (m_queue.empty() && m_open && now < waitUntil) {
      m_cv.wait_until(lock, waitUntil);
      now = std::chrono::system_clock::now();
    }
  }

  /*
   * Empty is the only reason to say "nothing", and not "closed": a session that is being torn down
   * still holds its client's last answers, and discarding them here would be exactly the silent loss
   * this class exists to stop. Closing stops the waiting, not the reading.
   */
  if(m_queue.empty()) return {};

  result = m_queue.front();
  m_queue.pop_front();

  lock.unlock();
  m_cv.notify_one();

  return result;

}

void EventStream::close() {
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_open = false;
  }
  m_cv.notify_all();
}

bool EventStream::isOpen() {
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_open;
}

v_uint32 EventStream::maxQueueSize() const {
  return m_maxQueueSize;
}

StreamStats EventStream::stats() const {
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_stats;
}

}}}
