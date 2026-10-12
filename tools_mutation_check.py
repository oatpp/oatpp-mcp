#!/usr/bin/env python3
"""
Mutation check for the security fixes in this module.

Revert one deliberate decision at a time, rebuild, and require the test suite to fail. A mutation
that nothing notices marks a decision the tests do not actually protect - which is a different
statement from "the tests pass", and the only one of the two that says anything about the future.

    python3 tools_mutation_check.py            # all mutations
    python3 tools_mutation_check.py --list     # what would be tried
    python3 tools_mutation_check.py --only 7   # one mutation, by number

Each entry is (description, file, text-to-revert, replacement). The pattern must match exactly once;
a pattern that matches nothing is reported as SKIPPED rather than silently passing, because a
mutation whose pattern did not survive a refactor is a hole in this file, not a clean run.

!! Do not `git commit` while this is running. It edits the working tree, and an `git add -A` in the
!! middle of it commits a mutation - which in `git show --stat` looks like nothing more than an
!! unrelated one-line change in an unrelated commit.
"""

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(ROOT, "build")

LISTENER = "src/oatpp-mcp/Listener.cpp"
LOGSAFE = "src/oatpp-mcp/utils/LogSafe.cpp"
SESSION = "src/oatpp-mcp/event/Session.cpp"
ACCESS = "src/oatpp-mcp/utils/AccessGuard.cpp"
CONTROLLER = "src/oatpp-mcp/sse/Controller.hpp"
EVENT_SERVER = "src/oatpp-mcp/event/Server.cpp"
EVENT_STREAM = "src/oatpp-mcp/event/EventStream.cpp"

# ---------------------------------------------------------------------------------------------
# F3 - remote denial of service on malformed messages
# ---------------------------------------------------------------------------------------------

PARSE_CATCH = """  } catch (const std::exception& e) {
    OATPP_LOGw("Listener", "[{}] undecodable message: {}", session.getId(),
               utils::LogSafe::text(e.what()))
    /* No id could be read, so the error goes out with a null id - JSON-RPC §5. */
    sendRpcError(session, nullptr, rpc_error::ParseError, "Parse error");
    return;
  }"""

PARAMS_CHECK = "  if(!paramsNode.isUndefined() && !paramsNode.isNull() && !paramsNode.isMap()) {"
ID_CHECK = "    if(!(idNode.isString() || idNode.isIntPrimitive() || idNode.isFloatPrimitive())) {"
METHOD_CHECK = "  if(!methodNode.isString()) {"
DISPATCH_TAIL = "  } else if(hasId) {"
NORMALISE = "  if(call->params == nullptr || call->params->isUndefined() || call->params->isNull()) {"

TOOLS_ARGUMENTS_CHECK = """  if(!isAbsentOrMap(callParams->arguments)) {
    sendInvalidParams(session, call, "tools/call", "'arguments' must be an object");
    return;
  }"""

TOOLS_REMAP = """  oatpp::Object<dto::ClientParamsToolsCall> callParams;
  try {
    callParams = m_remapper.remap<oatpp::Object<dto::ClientParamsToolsCall>>(call->params);
  } catch (const std::exception& e) {
    sendInvalidParams(session, call, "tools/call", e.what());
    return;
  }"""

LISTEN_GUARD = """    } catch (const std::exception& e) {
      OATPP_LOGe("[oatpp::mcp::Session::listen()]",
                 "Error - listener threw for session {}, continuing: {}", m_id, e.what())
    } catch (...) {
      OATPP_LOGe("[oatpp::mcp::Session::listen()]",
                 "Error - listener threw an unknown exception for session {}, continuing", m_id)
    }"""

# The idle-timeout rule, and the early wake that makes it fire on time rather than one ping late.
TTL_RULE = """      if(m_idleTimeout > std::chrono::milliseconds::zero()
         && (now - lastActivity) >= m_idleTimeout) {"""
TTL_WAKE = "        if(remaining < wait) {"

# F8 - the queue, its bound, and what is said when it refuses
QUEUE_BOUND = "    } else if(m_maxQueueSize > 0 && m_queue.size() >= m_maxQueueSize) {"
DROP_LOG = "  if(dropped == 1 || dropped % DropLogInterval == 0) {"
DRAIN_ON_CLOSE = "  if(m_queue.empty()) return {};"


def handler_remap(method, dto):
    """The wrapped parameter remap of one handler."""
    return f"""  try {{
    m_remapper.remap<oatpp::Object<dto::{dto}>>(call->params);
  }} catch (const std::exception& e) {{
    sendInvalidParams(session, call, "{method}", e.what());
    return;
  }}"""


MUTATIONS = [
    # (description, file, revert, replace, test)
    ("F3: parse error is not answered with -32700", LISTENER, PARSE_CATCH,
     "  } catch (const std::exception&) {\n    return;\n  }", "ListenerMessageTest"),

    ("F3: envelope does not check that params is an object", LISTENER, PARAMS_CHECK,
     "  if(false) {", "ListenerMessageTest"),

    ("F3: envelope does not check the id type", LISTENER, ID_CHECK,
     "    if(false) {", "ListenerMessageTest"),

    ("F3: envelope does not require a string method", LISTENER, METHOD_CHECK,
     "  if(false) {", "ListenerMessageTest"),

    ("F3: unknown method is ignored again (no -32601)", LISTENER, DISPATCH_TAIL,
     "  } else if(false) {", "ListenerMessageTest"),

    ("F3: notifications are answered too (-32601 whatever the id)", LISTENER, DISPATCH_TAIL,
     "  } else if(true) {", "ListenerMessageTest"),

    ("F3: absent params is not normalised to an empty object", LISTENER, NORMALISE,
     "  if(false) {", "ListenerMessageTest"),

    ("F3: tools/call does not check that arguments is an object", LISTENER, TOOLS_ARGUMENTS_CHECK,
     "  // mutated", "ListenerMessageTest"),

    ("F3: tools/call remap is not wrapped", LISTENER, TOOLS_REMAP,
     """  oatpp::Object<dto::ClientParamsToolsCall> callParams =
    m_remapper.remap<oatpp::Object<dto::ClientParamsToolsCall>>(call->params);
  do { if(false) { return; } } while(0);""", "ListenerMessageTest"),

    ("F3: prompts/list remap is not wrapped", LISTENER, handler_remap("prompts/list", "ClientParamsToolsList"),
     "  // mutated", "ListenerMessageTest"),

    ("F3: resources/list remap is not wrapped", LISTENER, handler_remap("resources/list", "ClientParamsResourceList"),
     "  // mutated", "ListenerMessageTest"),

    ("F3: initialize remap is not wrapped", LISTENER, handler_remap("initialize", "ClientParamsInitialize"),
     "  // mutated", "ListenerMessageTest"),

    # -------------------------------------------------------------------------------------------
    # F6 - attacker-controlled text in info-level logs
    # -------------------------------------------------------------------------------------------

    ("F6: the resolved request target is logged at info", LOGSAFE,
     '  OATPP_LOGd(tag, "request target:', '  OATPP_LOGi(tag, "request target:', "ToolLoggingTest"),

    ("F6: header values are logged at info", LOGSAFE,
     '  OATPP_LOGd(tag, "header:', '  OATPP_LOGi(tag, "header:', "ToolLoggingTest"),

    ("F6: the request body is logged at info", LOGSAFE,
     '  OATPP_LOGd(tag, "body:', '  OATPP_LOGi(tag, "body:', "ToolLoggingTest"),

    ("F6: the endpoint line is not rendered", LOGSAFE,
     """  OATPP_LOGi(tag, "tool '{}': {} {}", text(endpointName), text(method), text(pathPattern))""",
     """  OATPP_LOGi(tag, "tool '{}': {} {}", endpointName, method, pathPattern)""",
     "ToolLoggingTest"),

    ("F6: CR, LF and TAB are not escaped", LOGSAFE,
     r"""    case '\r': out += "\\r"; return;
    case '\n': out += "\\n"; return;
    case '\t': out += "\\t"; return;""",
     "    // mutated", "LogSafeTest"),

    ("F6: the remaining control characters are not escaped", LOGSAFE,
     "  if(byte < 0x20 || byte == 0x7F) {", "  if(false) {", "LogSafeTest"),

    ("F6: header values are not redacted", LOGSAFE,
     "  if(isSensitiveName(name)) {", "  if(false) {", "LogSafeTest"),

    ("F6: query parameter values are not redacted", LOGSAFE,
     "if(equals != std::string::npos && isSensitiveLowered(lowered(part.substr(0, equals)))) {",
     "if(false) {", "LogSafeTest"),

    ("F6: values are not truncated", LOGSAFE,
     "  const v_buff_size cut = cutIndex(value, maxLength);",
     "  const v_buff_size cut = static_cast<v_buff_size>(value.size());", "LogSafeTest"),

    ("F6: a cut may land inside a multi-byte character", LOGSAFE,
     """  while(i > 0 && i < size && isUtf8Continuation(value[i])) {
    i --;
  }""",
     "  // mutated", "LogSafeTest"),

    ("F3: session thread does not guard the listener call", SESSION, LISTEN_GUARD,
     """    } catch (const std::exception&) {
      throw;
    }""", "ListenerMessageTest"),

    # -------------------------------------------------------------------------------------------
    # F4 - Origin, Host, unknown sessions and the session limits
    # -------------------------------------------------------------------------------------------

    ("F4: the Origin rule does not run", ACCESS,
     "  if(m_config.checkOrigin && !trimmedOrigin.empty()) {", "  if(false) {",
     "AccessGuardTest"),

    ("F4: the Host allow-list does not run", ACCESS,
     "  if(!m_config.allowedHosts.empty()) {", "  if(false) {", "AccessGuardTest"),

    ("F4: any origin is treated as this server's own", ACCESS,
     "      allowed = originIsSelf(origin, host);", "      allowed = true;", "AccessGuardTest"),

    ("F4: Origin: null is accepted", ACCESS,
     '    if(trimmedOrigin == "null") {', "    if(false) {", "AccessGuardTest"),

    ("F4: a Host that merely contains an allowed name is accepted", ACCESS,
     """  if(hostName != entryName) {
    return false;
  }""",
     """  if(hostName.find(entryName) == std::string::npos) {
    return false;
  }""", "AccessGuardTest"),

    ("F4: the port of a Host entry is ignored", ACCESS,
     "  return entryPort.empty() || entryPort == hostPort;", "  return true;",
     "AccessGuardTest"),

    ("F4: GET sse does not consult the guard", CONTROLLER,
     """    if(auto refusal = reject(request, "GET sse")) {
      return refusal;
    }""",
     "    // mutated: the endpoint stopped asking", "SseAccessTest"),

    ("F4: POST sessions does not consult the guard", CONTROLLER,
     """    if(auto refusal = reject(request, "POST sessions")) {
      return refusal;
    }""",
     "    // mutated: the endpoint stopped asking", "SseAccessTest"),

    ("F4: an unknown session is answered 200 again", CONTROLLER,
     '''                 utils::LogSafe::text(sessionId))
      return createResponse(Status::CODE_404, "No such session");''',
     '''                 utils::LogSafe::text(sessionId))
      return createResponse(Status::CODE_200, "OK");''', "SseAccessTest"),

    ("F4: the session cap is not enforced", EVENT_SERVER,
     "if(m_config.maxSessions > 0 && m_sessions.size() >= m_config.maxSessions) {",
     "if(false) {", "SseAccessTest"),

    ("F4: an idle session is never closed", SESSION, TTL_RULE, "      if(false) {",
     "SseAccessTest"),

    ("F4: the loop does not wake for the idle timeout", SESSION, TTL_WAKE, "        if(false) {",
     "SseAccessTest"),

    # -------------------------------------------------------------------------------------------
    # F8 - a queue that has to refuse says so, to the caller, in the counters and to the log
    # -------------------------------------------------------------------------------------------

    ("F8: the queue does not bound itself", EVENT_STREAM, QUEUE_BOUND, "    } else if(false) {",
     "EventStreamTest"),

    ("F8: a refusal is reported to the caller as a delivery", EVENT_STREAM,
     "  if(result == PostResult::Queued) {", "  if(true) {", "EventStreamTest"),

    ("F8: a full queue is not counted", EVENT_STREAM,
     "      m_stats.droppedFull ++;", "      // mutated", "EventStreamTest"),

    ("F8: a closed stream is not counted", EVENT_STREAM,
     "      m_stats.droppedClosed ++;", "      // mutated", "EventStreamTest"),

    ("F8: a drop is not reported to the log", EVENT_STREAM, DROP_LOG, "  if(false) {",
     "EventStreamTest"),

    ("F8: every drop is logged, so a dead reader floods the log", EVENT_STREAM, DROP_LOG,
     "  if(true) {", "EventStreamTest"),

    ("F8: closing a stream discards what is still queued", EVENT_STREAM, DRAIN_ON_CLOSE,
     "  if(!m_open || m_queue.empty()) return {};", "EventStreamTest"),

    ("F8: a refused POST is answered 200 again", CONTROLLER,
     """      case event::PostResult::DroppedFull:
        break;""",
     """      case event::PostResult::DroppedFull:
        return createResponse(Status::CODE_200, "OK");""", "SseBackpressureTest"),

    ("F8: a closed session accepts the message again", CONTROLLER,
     """        return createResponse(Status::CODE_404, "No such session");

      case event::PostResult::DroppedFull:""",
     """        return createResponse(Status::CODE_200, "OK");

      case event::PostResult::DroppedFull:""", "SseBackpressureTest"),

    ("F8: the queue bound is not taken from the configuration", EVENT_SERVER,
     "      m_config.maxQueuedEvents);", "      EventStream::DefaultMaxQueueSize);",
     "SseBackpressureTest"),

    ("F8: a reply that could not be delivered is not reported", LISTENER,
     """  auto outcome = session.getOutStream()->post(event);
  if(!event::isQueued(outcome)) {
    /*
     * The work is done and the answer has nowhere to go.""",
     """  auto outcome = session.getOutStream()->post(event);
  if(false) {
    /*
     * The work is done and the answer has nowhere to go.""", "ListenerMessageTest"),
]


def run(argv):
    """
    Run a command and collect its output.

    `errors="replace"` is not a courtesy: a failing test prints the values it was given, and one of
    those values is deliberately a cut multi-byte character. Decoding strictly kills this tool while
    it is holding a mutated working tree, which is the worst possible moment to crash.
    """
    return subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, errors="replace")


def build():
    return run(["cmake", "--build", BUILD, "-j6"]).returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--list", action="store_true", help="list the mutations and exit")
    parser.add_argument("--only", type=int, metavar="N", help="run only mutation number N")
    args = parser.parse_args()

    if args.list:
        for i, (name, *_rest) in enumerate(MUTATIONS, 1):
            print(f"{i:2d}  {name}")
        return 0

    selected = [(i, m) for i, m in enumerate(MUTATIONS, 1)
                if args.only is None or i == args.only]
    if not selected:
        print(f"no such mutation: {args.only}", file=sys.stderr)
        return 2

    paths = sorted({m[1] for _i, m in selected})
    originals = {p: open(os.path.join(ROOT, p)).read() for p in paths}

    def restore():
        for p, text in originals.items():
            with open(os.path.join(ROOT, p), "w") as f:
                f.write(text)

    caught, missed, skipped = [], [], []
    try:
        for i, (name, path, old, new, test) in selected:
            restore()
            text = originals[path]
            if text.count(old) != 1:
                print(f"[{i:2d}] SKIPPED - pattern matched {text.count(old)} times in {path}: {name}")
                skipped.append(name)
                continue

            with open(os.path.join(ROOT, path), "w") as f:
                f.write(text.replace(old, new))

            if not build():
                print(f"[{i:2d}] SKIPPED - mutation does not compile: {name}")
                skipped.append(name)
                continue

            result = run(["./build/test/module-tests", f"--test={test}"])
            if result.returncode == 0:
                print(f"[{i:2d}] NOT CAUGHT: {name}")
                missed.append(name)
            else:
                summary = next((l.split("TEST[")[-1] for l in result.stdout.splitlines()
                                if "checks passed" in l), "test failed")
                print(f"[{i:2d}] caught    ({summary.strip()}) : {name}")
                caught.append(name)
    finally:
        restore()
        build()

    total = len(caught) + len(missed) + len(skipped)
    print(f"\n{len(caught)} caught, {len(missed)} not caught, {len(skipped)} skipped, of {total}")
    for label, items in (("NOT CAUGHT", missed), ("SKIPPED", skipped)):
        for item in items:
            print(f"  {label}: {item}")
    return 1 if (missed or skipped) else 0


if __name__ == "__main__":
    sys.exit(main())
