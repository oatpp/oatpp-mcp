//
// Created by Leonid S on 12/8/24.
//

#include "ReadCallback.hpp"

#include "oatpp-mcp/utils/LogSafe.hpp"

#include "oatpp/data/stream/BufferStream.hpp"
#include "oatpp/base/Log.hpp"

namespace oatpp { namespace mcp { namespace sse {

ReadCallback::ReadCallback(const std::shared_ptr<event::Session>& session, const oatpp::String& apiPrefix)
  : m_session(session)
  , m_initialized(false)
{
  if(apiPrefix && !apiPrefix->empty()) {
    oatpp::data::stream::BufferOutputStream ss(128);
    if(apiPrefix->data()[0] != '/') {
      ss << "/";
    }
    ss << apiPrefix;
//    if(apiPrefix->data()[apiPrefix->length() - 1] != '/') {
//      ss << "/";
//    }
    ss << "sessions/";
    m_apiPrefix = ss.toString();
  } else {
    m_apiPrefix = "/sessions/";
  }
}

ReadCallback::~ReadCallback()  {
  OATPP_LOGd("[oatpp::mcp::sse::ReadCallback::~ReadCallback()]", "Closing session")
  m_session->close();
}

oatpp::String ReadCallback::initEvent() {

  event::Event event;
  event.name = "endpoint";
  event.data = m_apiPrefix + m_session->getId();

  oatpp::data::stream::BufferOutputStream ss(256);
  ss << "event: " << event.name << "\n";
  ss << "data: " << event.data << "\n\n";
  return ss.toString();
}

oatpp::String ReadCallback::waitEvent() {

  auto event = m_session->getOutStream()->read(std::chrono::milliseconds(0) /* wait until event */);

  /*
   * Outbound, but not therefore safe: a tool result often contains text the tool read from wherever
   * the tool reads, and this line is the one place that text is written to the log.
   */
  OATPP_LOGd("Event", "[{}] <-- : {}", m_session->getId(),
             oatpp::mcp::utils::LogSafe::text(event.data, oatpp::mcp::utils::LogSafe::MaxMessageLength))

  if(event) {
    oatpp::data::stream::BufferOutputStream ss(256);
    ss << "event: " << event.name << "\n";
    ss << "data: " << event.data << "\n\n";
    return ss.toString();
  }

  return nullptr;

}

oatpp::v_io_size ReadCallback::read(void *buffer, v_buff_size count, oatpp::async::Action &action) {

  if(m_inlineData.bytesLeft == 0) {
    if(m_initialized) {
      m_currMessage = waitEvent();
    } else {
      m_currMessage = initEvent();
      m_initialized = true;
    }
    if(m_currMessage) m_inlineData.set(m_currMessage->data(), m_currMessage->size());
  }

  v_buff_size desiredToRead = m_inlineData.bytesLeft;
  if (desiredToRead > 0) {
    if (desiredToRead > count) desiredToRead = count;
    std::memcpy(buffer, m_inlineData.currBufferPtr, desiredToRead);
    m_inlineData.inc(desiredToRead);
    return desiredToRead;
  }

  return 0;

}

}}}