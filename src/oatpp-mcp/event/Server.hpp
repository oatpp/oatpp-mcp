//
// Created by Leonid S on 12/8/24.
//

#ifndef OATPP_MCP_EVENT_SERVER_HPP
#define OATPP_MCP_EVENT_SERVER_HPP

#include "Session.hpp"

#include <unordered_map>

namespace oatpp { namespace mcp { namespace event {

class Server {
private:

  struct Handle {
    std::unordered_map<oatpp::String, std::shared_ptr<Session>> sessions;
  };

private:
  std::shared_ptr<Handle> m_handle;
  std::shared_ptr<Session::Pinger> m_pinger;
public:

  Server(const std::shared_ptr<Session::Pinger>& pinger = nullptr);

  std::shared_ptr<Session> startNewSession(const std::shared_ptr<Session::EventListener>& listener);

  std::shared_ptr<Session> getSession(const oatpp::String& sessionId) const;

};

}}}

#endif //OATPP_MCP_EVENT_SERVER_HPP