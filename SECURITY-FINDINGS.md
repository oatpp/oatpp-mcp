# Security findings — oatpp-mcp

Durable record of the vulnerabilities reported against this module, what was verified on this
tree, and where the fix landed. **Update the status column as the fix PRs merge** — this file is
the thread that runs through them.

Verified against `main` @ `fee4651` with oatpp 1.4.0. Everything marked *verified* was reproduced
by running the code, not by reading it.

## Status

| ID | Finding | Severity | Status | Test |
|----|---------|----------|--------|------|
| [F1](#f1--request-smuggling-via-tool-arguments) | Request smuggling via tool arguments | High | **fixed** | `HttpSanitizeTest`, `ToolHttpFramingTest` |
| [F2](#f2--session-identifiers-are-heap-addresses) | Session identifiers are heap addresses | High | **open — reproduced** | `SessionIdTest` |
| [F3](#f3--remote-denial-of-service-on-malformed-messages) | Remote DoS on malformed messages | High | **open — reproduced** | `ListenerMessageTest` |
| [F4](#f4--no-origin-host-or-peer-validation-on-the-sse-endpoints) | No Origin/Host/peer validation on the SSE endpoints | Medium | open | — |
| [F5](#f5--two-blocked-threads-per-sse-connection) | Two blocked threads per SSE connection | Medium | open | — |
| [F6](#f6--attacker-controlled-text-in-info-level-logs) | Attacker-controlled text in info-level logs | Medium | open | — |
| [F7](#f7--apibridge-cannot-be-stopped) | `ApiBridge` cannot be stopped | Medium | open | — |
| [F8](#f8--dropped-events-are-silent) | Dropped events are silent | Low | open | — |
| [F9](#f9--capability-registries-are-not-thread-safe) | Capability registries are not thread safe | Low | open | — |
| [F10](#f10--no-body-size-limit-and-no-rate-limiting) | No body size limit, no rate limiting | Low | open | — |

F1, F2 and F3 were reported by an external disclosure. F4–F10 were found while verifying them.

**Consequence of F1's fix that upstream should know about:** oatpp never percent-decodes a URL.
`Url::Parser::parseQueryParams()` and the router's path-variable labels hand the endpoint the raw
bytes, and `oatpp::encoding::Url::decode()` is not called from anywhere in the library. An endpoint
therefore receives `hello%20world` where the tool caller meant `hello world`. Nothing that worked
before regresses — a value containing a space used to produce a malformed request line — but the
correct end state needs the server side to decode as well. Tracked as **B6** below.

## Running the tests

```
cmake -S . -B build && cmake --build build
ctest --test-dir build                 # each test in its own process
build/test/module-tests --list         # what is registered
build/test/module-tests --test=SessionIdTest
```

`mcp-server-demo` (formerly also called `module-tests`) is the manual playground on port 3001 and
is not a test. See [test/CMakeLists.txt](test/CMakeLists.txt) for how tests are registered.

---

## F1 — request smuggling via tool arguments

**Where:** `src/oatpp-mcp/capabilities/Tool.cpp` — `prepareEndpointPath()`,
`prepareEndpointHeaders()`.

A tool call is turned into an HTTP request and executed by an oatpp `HttpRequestExecutor`. The
arguments end up in the request verbatim:

| value | path | encoded? |
|---|---|---|
| path variable | `Pattern::reconstruct()` writes `params.at(name)` straight into the path | **no** |
| query parameter | `ss << param.name << "=" << it->second` | **no** |
| header parameter | `Headers::put(name, value)` | **no** |
| body | serialized by a content mapper | yes (JSON escaping) |

Nothing downstream rejects CR or LF either: `outgoing::Request::send()` writes
`method + " " + "/" + path + " " + "HTTP/1.1\r\n"` and `http::Utils::writeHeaders()` writes
`name: value\r\n` without looking at what they are given. An argument containing `\r\n` therefore
ends the request line or the header block and starts a new request, which the upstream executes as
though the MCP client had sent it.

**Verified.** Against the demo server, one `tools/call` of `getUsers` executed both `getUsers` and
a smuggled `GET /users/42`:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"getUsers",
 "arguments":{"offset":"1","limit":"1",
              "searchPhrase":"x HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET /users/42 HTTP/1.1\r\nX-Second: 2\r\n\r\n"}}}
```

```
D UserController:getUsers
D UserController:getUserById     <- never requested
```

`ToolHttpFramingTest` reproduces this in-process (query parameter, path variable and header
injection) and asserts on what the *upstream endpoint observed*, because the caller always gets a
normal-looking answer.

**Note on the disclosed payload.** It injects `\r\n\r\n` directly after a path variable, which
produces a request line with no HTTP version; oatpp 1.4.0's `Parser::parseRequestStartingLine()`
requires one and answers 400, so that exact payload does not split a request here. That is an
accident of this upstream parser, not a defence: the payload above needs no parser bug and works
today, and a deployment whose tool upstream is a real HTTP server or a proxy has no such luck.

**Fix — landed.** `src/oatpp-mcp/utils/HttpSanitize.{hpp,cpp}`, used from `EndpointTool`:

| value | rule | why |
|---|---|---|
| path variable | percent-encoded (`encodePathSegment`) | encoding is lossless; the upstream gets what the caller meant |
| query name and value | percent-encoded (`encodeQueryComponent`) | same |
| header name, header value | **rejected** if not RFC 9110 `tchar` / `field-value` | there is no encoding for a header; stripping CR/LF would silently send a different header |
| assembled request target | final CR/LF/NUL guard (`validateRequestTarget`) | cheap insurance; fires only on a malformed endpoint pattern |
| body | unchanged | already serialized by a mapper; `ToolHttpFramingTest` pins this |

- The encoded set is RFC 3986 unreserved plus `!'()*`; everything else — including `%`, `/`, `?`,
  `#`, `&`, `=`, `+` and every control character — becomes `%XX`.
- **Input is always treated as raw**: `a%20b` becomes `a%2520b`. There is no sound way to tell a
  pre-encoded value from a literal one, so the distinction is not offered.
- Path variables are encoded before `Pattern::reconstruct()` is called, so the module does not
  depend on a base-project change; `reconstructEncoded()` (B3) is still worth having upstream.
- A rejected header throws `std::invalid_argument`, which `Listener::toolsCall` already turns into
  an MCP tool error.

Verified end-to-end against the demo server: the payload above now sends
`?searchPhrase=x%20HTTP%2F1.1%0D%0A…` and only `UserController:getUsers` runs. Legitimate calls are
unaffected — `getUserById(42)` still returns the user, and a search phrase containing spaces, `&`,
`=` and `%` now produces a well-formed request where it previously produced a truncated one.

Defence in depth belongs in oatpp itself (reject CR/LF when serializing a request target and
headers; add `Pattern::reconstructEncoded()`; decode what was encoded — B6); see below.

---

## F2 — session identifiers are heap addresses

**Where:** `src/oatpp-mcp/event/Session.cpp` — `Session::getId()` returns
`reinterpret_cast<v_uint64>(this)` formatted as decimal.

**Verified.** `SessionIdTest` reports the identifier and the object address side by side:

```
FAILED: identifier is not the address of the Session object | id=192059764978560, &Session=192059764978560
FAILED: no identifier is reissued across create/close cycles | unique=1 of 200
```

`unique=1 of 200`: create and close a session in a loop and the allocator hands back *the same
address every time*. An attacker who opens a session, notes the identifier and closes it has
predicted the identifier of the next client, and can then POST messages to it — `POST
/mcp/sessions/{sessionId}` authenticates nothing (F4), so those messages are delivered to the
victim's SSE stream.

**Fix.** Generate a random version-4 UUID once, in the `Session` constructor, and return it from
`getId()`. Use `std::random_device` directly — **not** `oatpp::utils::Random`, which is
`std::mt19937` and not cryptographically random. Identifiers must be stable across calls and must
not be derived from anything an attacker can observe.

---

## F3 — remote denial of service on malformed messages

**Where:** `src/oatpp-mcp/Listener.cpp` — `onEvent()` and every per-method handler.

`m_mapper.readFromString<Tree>(...)` throws `MappingError` on input that is not valid JSON, and
each handler calls `m_remapper.remap<Object<...>>(call->params)` *outside* its own `try` block. The
session runs on a detached thread with no handler, so any of this reaches `std::terminate` and the
process aborts. One unauthenticated POST is enough.

**Verified.** `ListenerMessageTest` drives `Listener::onEvent()` with a corpus; 7 of its rows threw
(where nothing should escape at all), including the disclosed empty body:

```
FAILED: no exception escapes onEvent(): empty POST body (the disclosed PoC) | thrown: [json]: Unknown character.
FAILED: no exception escapes onEvent(): truncated garbage | thrown: ... 'null' expected
FAILED: no exception escapes onEvent(): params is a number | thrown: ... TreeChildrenOperator(): Node type is NOT suppoerted
FAILED: no exception escapes onEvent(): params is an array | thrown: ... getPair(): Node type doesn't support pairs
FAILED: no exception escapes onEvent(): params is a string | thrown: ...
FAILED: no exception escapes onEvent(): params.name is a number | thrown: ... mapString(): Node is NOT a STRING
FAILED: no exception escapes onEvent(): method is a number | thrown: ...
```

The reported "empty body" case is one instance of a missing error path, not the whole of it. The
same test also pins two things the fix must not break (`tools/list`, `ping`, unknown tool) and one
that is wrong today: a request with an `id` and an unknown method is currently **ignored**, where
JSON-RPC requires a `-32601` reply.

**Fix.** Three layers:

1. validate the envelope before dispatch — parseable, a map, `method` a string, `params` absent or
   a map, `id` string/number/null — and answer `-32700` / `-32600` / `-32601`;
2. wrap dispatch in `try`/`catch` and answer `-32603`; move each handler's `remap` inside its `try`;
3. wrap `Session::listen()` so that no listener exception can reach `std::terminate`. A session
   dies before the process does.

Keep the client-facing message generic and log the detail server-side: today `e.what()` from the
JSON mapper is echoed straight back to the caller.

---

## F4 — no Origin, Host or peer validation on the SSE endpoints

**Where:** `src/oatpp-mcp/sse/Controller.hpp`.

`GET /sse` and `POST /sessions/{id}` accept any `Origin`, any `Host`, and any peer address; there is
no authentication of any kind. Unknown session identifiers are answered `200 OK` rather than `404`,
so guessing cannot even be distinguished from a live session, and a browser page can drive a
localhost MCP server through DNS rebinding (the MCP specification requires the Host/Origin check
for exactly this reason).

This is what turns F2 from a weakness into an attack. **Fix:** reject cross-origin `Origin` and
unexpected `Host` (configurable allow-list), answer `404` for unknown sessions, optionally bind a
session to the peer address that opened it.

## F5 — two blocked threads per SSE connection

**Where:** `src/oatpp-mcp/event/Server.cpp` (`startNewSession` detaches a thread per session) and
`src/oatpp-mcp/sse/ReadCallback.cpp` (the connection thread blocks in `EventStream::read` for the
lifetime of the connection). `HttpConnectionHandler` is itself thread-per-connection with no cap.

N idle SSE clients cost 2N threads and nothing limits N. **Fix:** cap sessions, add an idle TTL, and
document the thread cost; ideally drive the SSE body with oatpp's async/streaming facilities instead
of a blocked worker.

## F6 — attacker-controlled text in info-level logs

**Where:** `src/oatpp-mcp/capabilities/Tool.cpp` — `OATPP_LOGi` prints the full request path, every
header value and (at debug level) the request body.

Two problems: credentials and PII end up in logs, and the text is not sanitized, so a `\n` in an
argument forges log lines — the F1 payload does this on every invocation. **Fix:** log at debug,
truncate, and escape control characters.

## F7 — `ApiBridge` cannot be stopped

**Where:** `src/oatpp-mcp/utils/ApiBridge.cpp`.

`run()` creates two `oatpp::network::Server`s on the stack and joins them; the threads capture
`this`, so the object can neither be destroyed nor shut down.

**Destroying an `ApiBridge` aborts the process.** Its constructor creates an
`oatpp::async::Executor`, and `Executor::~Executor() = default` (`oatpp/async/Executor.hpp`) while
its workers still own joinable `std::thread`s — so `~ApiBridge` destroys a joinable thread:

```
terminate called without an active exception
```

This is what `ToolHttpFramingTest` hit first; the fixture is now deliberately leaked, with the
reason in the code, and the object-leak check for that test is disabled in the runner
(`test/oatpp-mcp/tests.cpp`). Embedding an MCP server in an application that wants a clean shutdown
is not possible either. The async half is also dead: `m_asyncConnectionHandler` is built with
`m_router` instead of `m_asyncRouter`, and the second thread body in `run()` never calls
`server.run()`, so `getAsyncHttpExecutor()` returns an executor with no server behind it.

**Fix:** hold the servers as members, add `stop()` (stopping the executor and the interface too),
and either wire the async router properly or remove the async accessors until they work.

## F8 — dropped events are silent

**Where:** `src/oatpp-mcp/event/EventStream.cpp` — `post()` returns void and drops the event when
the queue is full (100) or the stream is closed. A slow SSE reader therefore makes the server
silently ignore valid RPC calls. **Fix:** return whether the event was queued and log/count drops.

## F9 — capability registries are not thread safe

**Where:** `src/oatpp-mcp/Listener.cpp` — `addTool()`, `addPrompt()` and `addResource()` mutate maps
and vectors that every session thread reads, with no synchronization. Registering a capability while
sessions are running is a data race. **Fix:** guard the registries, or document that capabilities
must be added before the server starts.

## F10 — no body size limit and no rate limiting

**Where:** `src/oatpp-mcp/sse/Controller.hpp` — `BODY_STRING(String, body)` reads the whole POST
body into memory. **Fix:** configure a maximum message size.

---

## Base project (oatpp)

Changes that belong upstream rather than here; the module fixes are sufficient on their own, these
are the second line of defence.

| ID | Change | File |
|----|--------|------|
| B1 | reject CR/LF/NUL in header names and values when serializing | `web/protocol/http/Http.cpp` (`Utils::writeHeaders`) |
| B2 | reject CR/LF/NUL in the request target before writing the request line | `web/protocol/http/outgoing/Request.cpp` |
| B3 | add `Pattern::reconstructEncoded()`; leave `reconstruct()` alone so existing callers do not double-encode | `web/url/mapping/Pattern.{hpp,cpp}` |
| B4 | `RequestHeadersReader::readHeadersSectionIterative()` sets the buffer position to the end of the peeked chunk instead of to the section end, so the header parse is handed bytes past `\r\n\r\n`. Benign today because `Parser::parseHeaders()` stops at the blank line | `web/protocol/http/incoming/RequestHeadersReader.cpp` |
| B5 | a CSPRNG-backed UUID helper, so modules stop hand-rolling identifiers from `std::mt19937` | new `utils/Uuid.hpp` |
| B6 | **percent-decode what was encoded.** `Url::Parser::parseQueryParams()` splits on `&`/`=` and hands out raw labels; path-variable labels are raw too; `encoding::Url::decode()` is never called anywhere in the library. A correctly-encoded request therefore delivers `%20` to the endpoint | `network/Url.cpp`, `web/protocol/http/incoming/Request.cpp` |
| B7 | `Executor::~Executor() = default` while workers own joinable threads — destroying a stopped-but-not-joined executor is `std::terminate` | `async/Executor.hpp` |

## Conventions for the fix PRs

- One finding per PR where possible; a PR that adds a failing test and the fix that turns it green
  is easier to review than either alone.
- Tests are table-driven and report every failed row (`test/oatpp-mcp/tests/TestChecks.hpp`) rather
  than aborting on the first `OATPP_ASSERT`.
- Security properties are asserted on what the *upstream endpoint observed*, not on what the tool
  returned — the attack returns a normal answer.
- Every test is listed once, in `MCP_TESTS` in `test/CMakeLists.txt` and in the registry in
  `test/oatpp-mcp/tests.cpp`.
