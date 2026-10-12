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
| [F2](#f2--session-identifiers-are-heap-addresses) | Session identifiers are heap addresses | High | **fixed** | `UuidTest`, `SessionIdTest` |
| [F3](#f3--remote-denial-of-service-on-malformed-messages) | Remote DoS on malformed messages | High | **fixed** | `ListenerMessageTest` |
| [F4](#f4--no-origin-host-or-peer-validation-on-the-sse-endpoints) | No Origin/Host/peer validation on the SSE endpoints | Medium | **fixed** | `AccessGuardTest`, `SseAccessTest` |
| [F5](#f5--two-blocked-threads-per-sse-connection) | Two blocked threads per SSE connection | Medium | partly fixed — bounded, still two threads each | `SseAccessTest` |
| [F6](#f6--attacker-controlled-text-in-info-level-logs) | Attacker-controlled text in info-level logs | Medium | **fixed** | `LogSafeTest`, `ToolLoggingTest` |
| [F7](#f7--apibridge-cannot-be-stopped) | `ApiBridge` cannot be stopped | Medium | open | — |
| [F8](#f8--dropped-events-are-silent) | Dropped events are silent | Low | **fixed** | `EventStreamTest`, `SseBackpressureTest`, `ListenerMessageTest` |
| [F9](#f9--capability-registries-are-not-thread-safe) | Capability registries are not thread safe | Low | open | — |
| [F10](#f10--no-body-size-limit-and-no-rate-limiting) | No body size limit, no rate limiting | Low | open | — |
| [F11](#f11--a-notification-with-a-known-method-is-answered) | A notification with a known method is answered | Low | open | `ListenerMessageTest` pins the unknown-method case |
| [F12](#f12--the-stdio-transport-dereferences-a-null-event-on-shutdown) | stdio dereferences a null event on shutdown | Low | **fixed** | contract pinned by `EventStreamTest`; the loop itself is not covered |

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

To check that the tests still *protect* the fixes rather than merely passing over them:

```
python3 tools_mutation_check.py            # revert one decision at a time; require a failure
python3 tools_mutation_check.py --list
python3 tools_mutation_check.py --only 7
```

It edits the working tree and rebuilds, so do not `git commit` while it runs. It currently covers
F3, F4, F6 and F8; extending it to the F1 and F2 decisions is task **T6.1**.

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

**Fix — landed.** `src/oatpp-mcp/utils/Uuid.{hpp,cpp}`, used from the `Session` constructor:
`m_id` is generated once and `getId()` returns it, so the identifier is stable for the lifetime of
the session and outlives nothing that could have been derived from the object.

| decision | what was chosen | why |
|---|---|---|
| format | UUID v4, canonical 8-4-4-4-12 lowercase, 122 random bits | a standard shape clients already handle, and a length that makes "is this an address?" a category error |
| entropy | `std::random_device` directly | **not** `oatpp::utils::Random` — that is `std::mt19937`, whose state is recoverable from its output; fine for shuffling, wrong for a capability |
| lifetime of the source | one process-wide source, allocated once, never destroyed | sessions run on detached threads that can call this during shutdown, after function-local statics are gone; a mutex destroyed under a waiting thread is worse than bytes the loader never reclaims |
| thread safety | mutex around `operator()` | the standard does not require `std::random_device::operator()` to be thread-safe on one object, and sessions are created on whichever thread served the request |
| entropy source unavailable | the exception propagates; no fallback | an identifier that is not random is the vulnerability itself. Failing to open a session is recoverable; failing silently is not |
| `random_device::entropy()` | deliberately **not** consulted | libc++ documents it as always returning 0, so a warning keyed on it is noise on exactly the platforms that are fine. It informs nothing; the source either works or throws |

Two supporting changes in `event/Server.cpp`, both about the same invariant:

- `startNewSession()` logs an error if an identifier is already in the registry. With 122 random
  bits this is not a race to be handled — it is the generator having stopped being random, and it
  must not be papered over by overwriting the session that got there first.
- the session's cleanup erases its registry entry **only if it is still its own**, so that if two
  sessions ever did share an identifier, the first to finish could not retire the second.

**Verified after the fix.** `UuidTest` 11/11 (format, lowercase, no repeats in 20 000 draws, no
long common prefix, every hex digit seen in the leading position, 10 000 draws from 4 threads all
distinct) and `SessionIdTest` 7/7 (identifier is not the object address, no reissue across 200
create/close cycles, longest common prefix ≤ 8). End-to-end against the demo server, the churn that
used to produce `unique=1 of 200` now produces 15 distinct identifiers out of 15 sequential SSE
connections, all canonical v4, longest common prefix 2:

```
56afe4ae-f74f-450f-922d-9ec6f4fc06b6   cfb8ba8b-d856-4a9a-bc8a-eac4d5aa99bc
63d097af-22b2-4a25-9e34-38a896ffc228   a635945e-661b-4a16-9ba0-305320814123
```

The SSE round-trip is unaffected: `tools/list` and `tools/call` still complete on a session
addressed by its UUID, and the F1 smuggling payload still produces one encoded request and one
controller call.

**What this does not fix.** The identifier is now unguessable, but the endpoints still authenticate
nothing else: no Origin/Host check, no peer binding, and an unknown identifier is still answered
`200 OK` rather than `404` — see F4. A random identifier raises the cost of hijacking a session from
"open a session and wait" to "guess 122 bits"; it does not make the session *authorized*.

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

**Fix — landed.** Three layers, as planned, in `Listener.cpp` and `event/Session.cpp`.

1. **Envelope validation** (`Listener::handleCall`, split out of `onEvent`) — parseable, a JSON
   object, `id` a string or number, `method` a string, `params` absent or an object — each failure
   answered with the code that describes it. An absent `params` is normalised to an empty object:
   remapping a *missing* node into a params DTO is one of the things that aborted the process, and
   every params field of every method is optional at the DTO level, so the handler — not the
   remapper — is what should report a missing required field.
2. **Every handler wraps its own parameter remap** and answers `-32602`; the tool/prompt/resource
   invocation `catch` blocks gained a `catch (...)` they did not have.
3. **`Session::listen()` wraps the listener call.** A listener is extension code, so "it cannot
   throw" is not a property of this library; an exception that reaches the top of that detached
   thread is `std::terminate`, and short of that the session is never removed from its server's
   registry. Log, drop the message, keep the session.

`onEvent()` keeps an outer `catch` as the last line, and it deliberately **does not reply**: by then
there is no way to know whether a response already went out for the id, and a second response to the
same id is a worse protocol violation than silence.

The error taxonomy, now visible to clients:

| situation | code | example |
|---|---|---|
| not JSON at all | `-32700` | the disclosed empty POST body, `"not json at all"`, binary junk |
| JSON, not a request object | `-32600` | `null`, `[1,2,3]` |
| `id` not a string/number | `-32600` | `"id":{…}` — and it is not reflected back |
| `method` missing or not a string | `-32600` | `"method":123` |
| `params` present and not an object | `-32600` | `"params":123`, `"params":[1]` |
| method exists, parameters do not fit | `-32602` | `"params":{"name":123}`, `"arguments":5`, `"cursor":123` |
| required field missing | `-32602` | `tools/call` with no `name` |
| unknown method **with an id** | `-32601` | previously a black hole: the client waited forever |
| unknown method **with no id** | *no reply* | a notification must not be answered (JSON-RPC §4.1) |
| a handler threw | `-32603` / `isError` result | detail logged, not sent |

**`e.what()` no longer goes to the client.** It was being placed straight into error messages and
into tool results; it now goes to the log, and the client gets `Invalid params` / `Internal error` /
`Tool handler thrown an exception`. A tool that wants the model to see its own failure text should
say so in an `isError` result it builds itself — that is a different channel from an exception that
happened to carry library internals.

**Verified.** `ListenerMessageTest` — 117 checks, all green — drives `onEvent()` with the corpus
above plus controls, asserts the **specific error code** (not merely that an error came back), that
control rows get a *result* rather than an error, that the registered tool ran or did not run, and —
for layer 3 — that a listener which throws three times leaves the session thread alive and reading.

The fix was then mutation-checked: **13 of 13 reverted decisions are caught by the suite** (swallow
the parse error, drop each of the four envelope checks, answer notifications anyway, drop the params
normalisation, unwrap each handler's remap, remove the `Session::listen` guard). Two of them were
*not* caught by the first version of the test — the parse-error reply and the params normalisation —
which is why the corpus now pins codes and why a control row has to be a result, not just "a reply".

End to end against the demo server: 19 malformed payloads (including the disclosed empty body and
binary junk) leave the process alive, and normal operation is unaffected — `tools/list`, `tools/call`
and `ping` still round-trip, `-32601` reaches the client for an unknown method, and a notification
for an unknown method gets no reply.

**Not fixed here:** see [F11](#f11--a-notification-with-a-known-method-is-answered).

---

## F4 — no Origin, Host or peer validation on the SSE endpoints

**Where:** `src/oatpp-mcp/sse/Controller.hpp`.

`GET /sse` and `POST /sessions/{id}` accept any `Origin`, any `Host`, and any peer address; there is
no authentication of any kind. Unknown session identifiers are answered `200 OK` rather than `404`,
so guessing cannot even be distinguished from a live session, and a browser page can drive a
localhost MCP server through DNS rebinding (the MCP specification requires the Host/Origin check
for exactly this reason).

This is what turns F2 from a weakness into an attack: a random identifier is only a capability while
nobody can obtain one, and "open a session and read the identifier the server hands back" obtained
one for free while the identifier was an address.

**Fix — landed.** `src/oatpp-mcp/utils/AccessGuard.{hpp,cpp}`, consulted by both endpoints of
`sse::Controller` before either does anything else, plus limits on the session registry in
`event::Server`.

| decision | what was chosen | why |
|---|---|---|
| `Origin` present | must equal this server's own origin (`http(s)://` + the request's `Host`) or be named in `allowedOrigins` | a browser sends `Origin` when the request is not same-origin; requiring agreement costs nothing to curl, the SDKs and a proxy, and removes the "any web page can drive the operator's localhost server" case outright |
| `Origin` absent | allowed | non-browser clients — the majority of MCP clients — send none. Requiring one would break them and would not stop an attacker, who can simply omit it |
| `Origin: null` | refused | what a sandboxed frame and a `file://` page send; neither is a place an MCP client should be coming from |
| origin scheme | not compared | TLS terminated in front of this server means the page is `https` and the `Host` header says nothing about it. Comparing schemes would break every such deployment to gain nothing |
| `Host` | if `allowedHosts` is non-empty, the header must match one entry — exact host, case-insensitive, port required only when the entry names one | the only check that can see DNS rebinding |
| `allowedHosts` default | **empty = any Host** | the library cannot know the addresses it is deployed on, and a wrong default here breaks the server rather than protecting it. The consequence is stated in the config's own documentation, logged once at startup when it is unset, and pinned by a test row that says the rebinding request is *accepted* under the default configuration |
| unknown session | `404`, was `200 OK` | a probe for an identifier used to be indistinguishable from a delivered message, to the client and to the operator's log alike. The body says no more than "No such session" — whether an identifier was once valid is not the caller's business |
| refused request | answered before the session is opened or the message is posted, with the rule named and the offending value only in the log | ordering is the fix: a check that runs after the work is a report, not a defence |
| `maxSessions` | 1000 by default, `0` for unlimited; a full server answers `503` | the number being *finite* is the point — see F5. Generous because refusing a client is a real cost, and 1000 concurrent SSE clients is far past what this server is likely to see |
| `sessionIdleTimeoutMillis` | 0 (never) by default | expiring a client that is connected but quiet is a behaviour change, and a stdio session in particular is expected to idle between tool calls. When set, the listen loop wakes for the timeout rather than only for the ping, so a session dies on time and not up to five seconds late |
| peer-address binding | **not implemented** | see "What this did not do" |

**Verified.** `AccessGuardTest` — 120 checks — is the policy as a table of (configuration, Origin,
Host) pairs, including the ones that are easy to get wrong: `localhost.evil.example` against an
allow-list entry of `localhost`, an IPv6 literal with and without a port, an origin with a path on
the end, a missing `Host` (400, not 403), and the rebinding request both refused (list configured)
and accepted (default configuration).

`SseAccessTest` — 24 checks — puts the real `sse::Controller` on a real socket, because "the endpoint
forgot to ask the guard" is invisible to a unit test of the guard. It asserts the status codes, that
a refused `GET /sse` opened **no** session, that a refused `POST` delivered **nothing** to the
session's listener, that a live session still receives its message unchanged, that a full server
answers 503 and then answers 200 again once a slot frees, and that an idle session is reclaimed
while a session with no timeout is left alone.

Twelve F4 decisions are in `tools_mutation_check.py` — stop checking Origin, stop checking Host, treat
any origin as self, accept `null`, match a Host as a substring, ignore the port, drop the guard from
either endpoint, answer 200 for an unknown session, skip the cap, never expire a session, and stop
waking the loop for the expiry. All twelve are caught; so are the F3 and F6 ones, **35 of 35**.

One of them was not caught to begin with. Removing the `Origin: null` branch leaves the request
refused anyway — a `null` origin is neither self nor named — so the only thing the branch changes is
the *message*, and no test looked at the message. Rather than delete the branch or the mutation, the
tests now pin the reason for the refusals where the reason is the answer an operator needs: "Origin
'null' is not allowed" is a sandboxed frame, "Host is not allowed" is a rebinding or a misconfigured
proxy, and "Missing Host header" is a client that should not have got this far.

End to end against the demo server, which now configures `{"localhost", "127.0.0.1"}`:

```
GET  /mcp/sse                               200      (no Origin: a native client)
GET  /mcp/sse   Origin: http://evil.example 403      rejected GET sse: Origin is not allowed
GET  /mcp/sse   Host: rebound.attacker...   403      rejected GET sse: Host is not allowed
GET  /mcp/sse   Origin: http://localhost:3001 200    (same-origin browser)
POST /mcp/sessions/<unknown>                404      no session to deliver to: <unknown>
```

and a real client is unaffected: `tools/list`, `tools/call getUserById` and the F1 smuggling payload
all return over the SSE stream, and the smuggling payload still runs exactly one controller —
`UserController:getUsers`, with the injected `GET /users/424242` percent-encoded into the query.

**What this did not do.**

- **Peer-address binding** ("the session may only be addressed from the address that opened it") is
  still open. With F2 fixed it defends a capability that is already unguessable, it breaks every
  deployment behind NAT or a proxy, and the two decisions worth making first — where the address
  comes from when the server is behind a proxy that sets `X-Forwarded-For`, and what to do about a
  client whose address legitimately changes — are deployment questions this module should not answer
  by guessing.
- **Authentication** of any kind. The MCP spec leaves it to the transport and the deployment; what
  this adds is that the server no longer pretends an identifier is an authenticator.
- **Message rate and body size** — see F10.

## F5 — two blocked threads per SSE connection

**Where:** `src/oatpp-mcp/event/Server.cpp` (`startNewSession` detaches a thread per session) and
`src/oatpp-mcp/sse/ReadCallback.cpp` (the connection thread blocks in `EventStream::read` for the
lifetime of the connection). `HttpConnectionHandler` is itself thread-per-connection with no cap.

N idle SSE clients cost 2N threads and nothing limited N.

**Partly fixed with F4.** `event::Server::Config::maxSessions` (default 1000) bounds N, and
`sessionIdleTimeoutMillis` reclaims a session whose client stopped talking but never hung up — the
idle timeout also unblocks the parked SSE writer, which is what frees the connection thread. What
remains is the model itself: two threads per client, one of them doing nothing but waiting.
**Fix:** drive the SSE body with oatpp's async/streaming facilities instead of a blocked worker, and
document the thread cost of the synchronous one.

**Also bounded with F8.** `event::Server::Config::maxQueuedEvents` (default 100, per session and per
direction) is the memory half of the same idle client: what a stalled reader accumulates used to be
one hundred messages because a constructor said so, and it is now a configuration an operator can see
and change.

One thing about F5 is **not** fixable from here, and it is worth being blunt about because it makes
`maxSessions` less protective than it looks: `HttpConnectionHandler` starts a thread for every
accepted connection, with no cap and no read timeout, so **N idle TCP connections cost N threads
before any MCP session exists**. A client that connects and sends nothing never reaches the session
registry at all. Recorded as **B8** in the base-project table below.

## F6 — attacker-controlled text in info-level logs

**Where:** `src/oatpp-mcp/capabilities/Tool.cpp` — `OATPP_LOGi` printed the resolved request path and
every header value, and the request body went out at debug. The same habit was still in
`Listener::onEvent()` and `sse::ReadCallback::waitEvent()`, which log whole messages.

Two problems, and they do not pull the same way:

- **a log is where secrets go to leak.** `Authorization` was just another header name among the ones
  an endpoint declares, and info is the level that is on by default and shipped somewhere else;
- **a log is a line-oriented sink.** A `\n` in anything written to it begins a new record — carrying
  this server's own timestamp and tag, which is exactly what makes it worth forging.

**Verified.** Forging a record did not need the F1 payload, and does not need the request to be
valid — a message is logged before the parser rejects it:

```
POST /mcp/sessions/<id>     body: "GARBAGE\n2026-10-11 00:00:00 FORGED RECORD from a tool client\n"

 D |...| Event:[<session>] --> : GARBAGE
 2026-10-11 00:00:00 FORGED RECORD from a tool client     <- not a record; a grep for a date says it is
```

(The F1 payload forged records through the resolved path too; encoding the arguments for F1 closed
that route and left this one.)

**Fix — landed.** `src/oatpp-mcp/utils/LogSafe.{hpp,cpp}`, used from `EndpointTool::call`,
`Listener` and `sse::ReadCallback`.

| decision | what was chosen | why |
|---|---|---|
| level | one info line per tool call naming the endpoint, its method and its **path pattern**; the resolved target, the headers and the body at debug | "which tool ran" is the operator's question — with a proxy blocking tools it is also the security question — so it survives the default level; what the caller sent does not need to |
| control characters | `\r`, `\n` and `\t` keep a readable two-character form; every other C0 control and DEL becomes `\xNN`; bytes >= 0x80 pass through | one record per input line, and the record still says what was in it — including text that is not ASCII |
| length | 1 KiB per value, 2 KiB per message, then `...[+N bytes]` | the budget is measured in *rendered* bytes, because that is what a log line has to stay inside; what was dropped is reported rather than hidden, and the cut never lands inside a multi-byte character |
| credentials | header values, and query-parameter values, whose name matches a known credential name become `<redacted>` | an escaped password is still a password; the name stays, because "which credential" is a fair question and "what was it" is not |
| scope | every value that reaches a log statement goes through this, including the developer-supplied endpoint name and path pattern | "nothing unrendered reaches the log" is then a property of the code, not of a list of call sites somebody decided were dangerous |

Redaction is best effort — it knows the common names, not this deployment's — and it is deliberately
not applied to bodies: a body is what somebody turned on debug logging to look at, and debug-only is
the control that was missing.

**Verified after the fix.** `LogSafeTest` 81/81 and `ToolLoggingTest` 26/26. The same POST is now one
record, and a tool call says what it ran without saying what it was sent:

```
 D |...| Event:[<session>] --> : GARBAGE\n2026-10-11 00:00:00 FORGED RECORD from a tool client\n...

 I |...| EndpointTool::call:tool 'getUsers': GET users/offset/{offset}/limit/{limit}/*
 D |...| EndpointTool::call:request target: '/users/offset/1/limit/1/?searchPhrase=x%20HTTP%2F1.1%0D%0A…'
```

Ten F6 decisions are in `tools_mutation_check.py` — log a value at info, stop escaping, stop
redacting a header or a query parameter, stop truncating, cut inside a multi-byte character — all
caught.

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

**Where:** `src/oatpp-mcp/event/EventStream.cpp` — `post()` returned `void` and discarded the event
when the queue was full (100) or the stream was closed.

A queue has to be finite, and a finite queue that refuses work has to say so. This one could not, so
nothing above it could tell a delivered message from a discarded one:

- `POST /mcp/sessions/{id}` answered **200 "OK"** to a message it had already thrown away. The client
  sat waiting for a response to a call the server never took.
- `Listener::sendRpcResult()` dropped the reply on the floor. "The server ignored a valid call" and
  "the client hung up" produced identical logs — that is to say, none.
- `stdioListen()` did the same to both of its threads, and additionally took apart the null event
  `read()` hands back once a session is closed — see **F12**.

The queue is not hypothetical. A hundred queued messages is what one client produces by pipelining
calls while its SSE reader is behind: a proxy buffering the stream, a client that opens the event
stream only after sending the calls, or a reader that died without the connection dying with it.

**Fix — landed.** `post()` reports what happened, and everyone who calls it does something with the
answer.

| decision | what was chosen | why |
|---|---|---|
| `post()` returns | `PostResult`: `Queued`, `DroppedFull`, `DroppedClosed` | an enum and not a bool — "retry later" and "never" are different answers to give a sender, and they used to be one silent outcome |
| `post()` on a full queue | refuses immediately; never blocks | the caller is a session thread or an HTTP connection thread. Backpressure would turn a lost message into a hung server, and the thread it blocks is the one that would notice the client died |
| `POST` over a full queue | `503` with `Retry-After: 1` | 200 is a claim about a message that was already discarded. 429 is about rate; this is capacity, and "not now" is the truth |
| `POST` to a closed session | `404` — the same answer as an unknown session | "this identifier used to be valid" is not for the transport to learn, and the two states are one line apart in a registry that forgets sessions by itself |
| counters | `EventStream::stats()` — queued, dropped-full, dropped-closed | a log record is a fact that happened once; a counter is what an operator alerts on, and what separates one hiccup from a client that has stopped reading |
| logging | warning, the first drop and then every 100th, with the running total in every record | a stream whose reader died drops forever. One record per drop trades a lost message for a log flood — the same availability problem one level down |
| what a drop record holds | event name, reason, limit, totals — never the payload | a drop is a transport fact; the data is whatever the tool read, and F6 is about not putting that in the log |
| a reply that cannot be queued | logged as a warning: session, reason, bytes lost | the outbound direction has no status code to carry the news, so the log is all there is and it has to be enough |
| events queued at `close()` | **drained, not discarded** | a session being torn down still holds its client's last answers. Closing stops the waiting, not the reading |
| the bound | `event::Server::Config::maxQueuedEvents`, default 100, `0` = unbounded, per session and per direction | the number used to be a literal in a constructor, invisible to the one person allowed to decide it. Per session, so a client that stopped reading cannot spend another client's capacity |

**API change.** `EventOutputStream::post()` returns `PostResult` instead of `void`, and
`EventStream::read()` now returns whatever is queued after a `close()` before reporting end-of-stream.
Callers that ignore the result are unaffected; anything implementing `EventOutputStream` has to change
its signature, and nothing in this module does.

**Verified.** `EventStreamTest` — 36 checks — is the queue as a table: FIFO; the bound refusing the
N+1'th event *without displacing what is already queued*; the two reasons counted separately;
close-then-drain; 1000 refusals in milliseconds (the "never blocks" property, timed rather than
asserted by faith); an unbounded queue accepting what it is given; and a producer/consumer pair
moving 5000 events through a queue of 8 with `queued + dropped == posted` and `delivered == queued`
— that last one is the drain, and it fails on the old code. The log is captured, not eyeballed: a
drop produces a record, 1000 drops produce ten of them, every record is one line, and the reason and
the running total are in it.

`SseBackpressureTest` — 23 checks — drives the real controller over a real socket with a listener
that can be stopped from taking messages, because "the queue is full" is not a state a test reaches
by asking a listener that keeps up to stop keeping up. It asserts 200 for a session that is reading;
503 — not 200, and not a body that says "OK" — for one that is not; a `Retry-After` on the 503; that
the refused messages **did not arrive**; that the endpoint accepts again once the queue drains; that
a closed-but-still-registered session answers 404; that a second session is unaffected while the
first is stalled; and that 50 pipelined messages to a default-configured session are all accepted —
the bound exists to bound memory, not to throttle working clients.

`ListenerMessageTest` gained the outbound half: with a session's out stream closed, the reply is
reported to the log with the reason it could not be delivered.

Eleven F8 decisions are in `tools_mutation_check.py` — unbind the queue, report a refusal as a
delivery, stop counting either kind of drop, silence the drop log, log every drop, discard on close,
answer 200 for a full queue, answer 200 for a closed session, ignore the configured bound, and stop
reporting an undeliverable reply. **All eleven are caught.**

## F9 — capability registries are not thread safe

**Where:** `src/oatpp-mcp/Listener.cpp` — `addTool()`, `addPrompt()` and `addResource()` mutate maps
and vectors that every session thread reads, with no synchronization. Registering a capability while
sessions are running is a data race. **Fix:** guard the registries, or document that capabilities
must be added before the server starts.

## F10 — no body size limit and no rate limiting

**Where:** `src/oatpp-mcp/sse/Controller.hpp` — `BODY_STRING(String, body)` reads the whole POST
body into memory. **Fix:** configure a maximum message size.

---

## F11 — a notification with a known method is answered

**Where:** `src/oatpp-mcp/Listener.cpp` — every handler ends in `sendRpcResult()`.

JSON-RPC 2.0 §4.1: a Notification is a request without an `id`, and the server **must not** reply to
it. Since the F3 fix, unknown-method notifications are correctly ignored — but a notification naming
a *known* method still gets a full response, addressed to `id: null`:

```
--> {"jsonrpc":"2.0","method":"tools/list"}
<-- {"jsonrpc":"2.0","result":{"tools":[…]}      <- no id came in, so none goes out either
```

Found while fixing F3, and deliberately left alone: the handlers do not currently know whether the
message had an `id`, threading that through every handler is a behaviour change for anyone whose
client omits ids and waits for replies, and MCP's own notifications (`notifications/initialized`,
`notifications/cancelled`) are unknown methods here and are already handled correctly — so nothing
in the disclosed attack surface depends on it.

**Fix:** pass the presence of an `id` down (or hand the handlers a small `Reply` object that knows
whether it may send), and suppress the response for notifications. `ListenerMessageTest` has the
`NoResponse` expectation ready for the rows this needs.

---

## F12 — the stdio transport dereferences a null event on shutdown

**Where:** `src/oatpp-mcp/Server.cpp`, `stdioListen()`:

```cpp
while (session->isOpen()) {
  auto e = session->getOutStream()->read(std::chrono::milliseconds(0));
  std::cout << *e.data << std::endl;      // e.data is null once the stream is closed
}
```

`read()` returns an invalid `Event` in exactly the situation this loop can reach: the stream has been
closed. `isOpen()` and "there is an event" are different questions, and the loop tested one and then
answered the other — so every clean shutdown of a stdio MCP server dereferenced a null
`oatpp::String`. Whether that reads as a crash or as silence is up to the allocator; it is undefined
either way, and it is on the normal exit path rather than under attack.

Found while fixing F8, because the fix is what made `read()`'s contract worth writing down.

**Fix — landed.** The loop reads until `read()` says there is nothing more, which with drain-on-close
(F8) also means it flushes what was queued before it exits. **Not covered by an automated test**:
`stdioListen()` reads the process's real stdin, and this suite has no harness for that. The contract
the loop depends on — `read()` returns an invalid event once a stream is closed *and drained*, and
nothing before that — is pinned by `EventStreamTest`.

**Still there, and deliberately not touched.** The same pair of threads means `stdioListen()` does not
return when its client closes stdin: `tin` finishes, nothing closes the session, and `tout` waits in
`read()` forever. Closing the session at stdin EOF would fix the hang and cut off any tool call still
running, which is a decision about in-flight work rather than a bug fix — so it is written down here
instead of being guessed at. It is unchanged by F12; the loop used to hang the same way and crash on
the way in.

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
| B5 | a CSPRNG-backed UUID helper, so modules stop hand-rolling identifiers from `std::mt19937`. `oatpp::utils::Random` is `std::mt19937` and is not a candidate for identifiers; `oatpp-mcp` grew its own (`utils/Uuid.{hpp,cpp}`, see F2) which is a suitable starting point if upstream wants one | new `utils/Uuid.hpp` |
| B6 | **percent-decode what was encoded.** `Url::Parser::parseQueryParams()` splits on `&`/`=` and hands out raw labels; path-variable labels are raw too; `encoding::Url::decode()` is never called anywhere in the library. A correctly-encoded request therefore delivers `%20` to the endpoint | `network/Url.cpp`, `web/protocol/http/incoming/Request.cpp` |
| B7 | `Executor::~Executor() = default` while workers own joinable threads — destroying a stopped-but-not-joined executor is `std::terminate` | `async/Executor.hpp` |
| B8 | `HttpConnectionHandler::handleConnection()` starts a `std::thread` per accepted connection with no cap and no read timeout, so a client that connects and sends nothing costs a thread without ever opening a session — `event::Server::Config::maxSessions` cannot bound it, and nothing else in the library does. A configurable connection cap, and a timeout on a connection that never sends a request, belong here | `web/server/HttpConnectionHandler.cpp` |

## Conventions for the fix PRs

- One finding per PR where possible; a PR that adds a failing test and the fix that turns it green
  is easier to review than either alone.
- Tests are table-driven and report every failed row (`test/oatpp-mcp/tests/TestChecks.hpp`) rather
  than aborting on the first `OATPP_ASSERT`.
- Security properties are asserted on what the *upstream endpoint observed*, not on what the tool
  returned — the attack returns a normal answer.
- Every test is listed once, in `MCP_TESTS` in `test/CMakeLists.txt` and in the registry in
  `test/oatpp-mcp/tests.cpp`.
