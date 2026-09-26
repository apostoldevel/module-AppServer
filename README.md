[![ru](https://img.shields.io/badge/lang-ru-green.svg)](README.ru-RU.md)

App Server
-

**Module** for **Apostol CRM**[^crm].

Description
-

**App Server** is a C++ HTTP/RESTful server module for the [Apostol (C++20)](https://github.com/apostoldevel/libapostol) framework. It runs inside Apostol worker processes and handles all incoming HTTP requests routed to the `/api/` path prefix.

Key characteristics:

* Written in C++20 using an asynchronous, non-blocking I/O model based on the **epoll** API — suitable for high-throughput, low-latency deployments.
* Connects directly to **PostgreSQL** via the `libpq` library. Every API request is dispatched to a PL/pgSQL function in the database; all business logic lives in the database, not in the module itself.
* Implements **REST** (Representational State Transfer) conventions for remote procedure calls over HTTP.
* Supports multiple authentication methods: **Bearer JWT** token, **Session + Secret** headers, and **Cookie-Based** authentication (`__Secure-AT`).
* Response format is always `application/json`.
* Built-in endpoints (`/ping`, `/time`) require no database interaction and are handled entirely in C++. All other endpoints are forwarded to the PostgreSQL `daemon` schema functions.

### How it fits into Apostol

Apostol runs a master process that forks N worker processes. Each worker loads a set of modules. `AppServer` is one such module — it registers itself as the handler for any request whose path starts with `/api/`. When a matching request arrives:

1. The worker's event loop (epoll) accepts the connection and reads the HTTP request.
2. `AppServer` inspects the `Authorization` header to determine the authentication context.
3. Based on the authentication result, it constructs a parameterised SQL call and submits it to the PostgreSQL connection pool asynchronously:
   - **Bearer JWT** (valid token) → `daemon.fetch`
   - **Session + Secret** headers → `daemon.session_fetch`
   - **No credentials** → `daemon.unauthorized_fetch`
   - **Expired token** with refresh cookie → auto-refreshes via `daemon.refresh_token`, then calls `daemon.fetch` with the new token
4. When the query result arrives, the module serialises it as JSON and sends the HTTP reply.

Documentation
-

REST API
-

### General information

* Base endpoint: [http://localhost:8080](http://localhost:8080)
* All endpoints return a **JSON object**.
* All time and timestamp fields are in **milliseconds** (Unix epoch).

### HTTP status codes

* `2XX` — success.
* `4XX` — client error (malformed request, authentication failure, resource not found, etc.).
* `5XX` — server error. The outcome of the operation is **unknown** — do not assume failure without verifying.

### Error response format

Any endpoint may return an error. The response body will contain an `error` object:

```json
{
  "error": {
    "code": 404,
    "message": "Not Found"
  }
}
```

Error codes >= 10000 are divided by 100 to map to standard HTTP status codes (e.g. 40401 → 404).

### Endpoint conventions

* For `GET` endpoints, all parameters are passed as **query string** values.
* For `POST` endpoints, parameters may be sent as a query string or as the request body. Supported content types for the request body:
  * `application/json`
  * `application/x-www-form-urlencoded`
  * `multipart/form-data`
* Parameters may be sent in any order.
* The module accepts `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS`. All other HTTP methods return `405 Method Not Allowed`.

### Response shaping (optional query parameters)

Two optional query parameters influence how PostgreSQL query results are serialised:

| Parameter | Allowed values | Effect |
|-----------|----------------|--------|
| `result_object` | `true`, `false` | When `true`, wraps the result in `{"result": ...}` |
| `result_format` | `object`, `array`, `null` | Forces the JSON serialisation format of the result set. Paths containing `/list` default to `array`. |

API Access
-

Access requires a **Bearer access token**, **Session + Secret** headers, or **Cookie-Based** authentication.

### Bearer token (JWT)

The access token **must** be present in the `Authorization` HTTP header of every authenticated request.

Format:

```
Authorization: Bearer <access_token>
```

The access token is a JSON Web Token ([RFC 7519](https://tools.ietf.org/html/rfc7519)). It is issued by the [AuthServer](https://github.com/apostoldevel/module-AuthServer) module (which is part of the same Apostol application).

The module validates the token locally using the configured provider secrets/keys before forwarding the request to the database. Supported algorithms: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512.

Tokens are also accepted from the `__Secure-AT` cookie (set by the server after login); the accompanying refresh token is read from `__Secure-RT`.

**Example request:**

```http
GET /api/v1/whoami HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiIDogImFjY291bnRzLnNoaXAtc2FmZXR5LnJ1IiwgImF1ZCIgOiAid2ViLXNoaXAtc2FmZXR5LnJ1IiwgInN1YiIgOiAiZGZlMDViNzhhNzZiNmFkOGUwZmNiZWYyNzA2NzE3OTNiODZhYTg0OCIsICJpYXQiIDogMTU5MzUzMjExMCwgImV4cCIgOiAxNTkzNTM1NzEwfQ.NorYsi-Ht826HUFCEArVZ60_dEUmYiJYXubnTyweIMg
```

Built-in Endpoints
-

These endpoints are handled entirely in C++ and require no database access or authentication.

### Ping

```http
GET /api/v1/ping
```

Tests connectivity to the REST API.

**Parameters:** none

**Response:**

```json
{}
```

### Server time

```http
GET /api/v1/time
```

Tests connectivity and returns the current server time.

**Parameters:** none

**Response:**

```json
{
  "serverTime": 1583495795455
}
```

`serverTime` is the number of milliseconds since the Unix epoch (UTC).

Application-specific Endpoints
-

All paths under `/api/` that are not handled by the built-in endpoints above are forwarded to PostgreSQL. The database function called depends on the authentication context:

| Context | PostgreSQL function |
|---------|---------------------|
| Bearer JWT token | `daemon.fetch(token, method, path, payload, agent, host)` |
| Session + Secret headers (Basic) | `daemon.session_fetch(session, secret, method, path, payload, agent, host)` |
| No credentials (when enabled) | `daemon.unauthorized_fetch(method, path, payload, agent, host)` |

The full set of application endpoints is therefore defined entirely in the project's database, in the `daemon` schema PL/pgSQL functions. **See your project's repository for endpoint documentation.**

### Guest routes

`module.AppServer.guest_routes` — a list of full request paths (`/api/v1/…`, no query string; exact match). A request **without credentials** to one of them is executed by `daemon.fetch` under the module's own service token — the `service` client of the `default` provider, its secret from the configuration — instead of `daemon.unauthorized_fetch`. It is for the sign-in screen's registration and recovery calls, which a browser cannot make with a client credential of its own (RFC 6749 §2.1, §4.4). A request with credentials, and a path outside the list, are handled as before. Default: empty.

- The token is minted on the heartbeat; until then (the first second of a worker) a guest route answers `503` with `Retry-After: 1`.
- Every guest shares **one** service session per worker. If the database closes it (a rate limiter that signs the calling session out, for example), the request answers `503` `Retry-After: 1` and the next heartbeat mints a new one. Limits meant per client have to key on the client's address, not on the session.
- `daemon.fetch` does not consult the blacklist that `daemon.unauthorized_fetch` does: a route put in this list bypasses it.

### Reusing the authorisation with another execution step

The step that runs the request is the virtual `execute()`. A module that needs the same authorisation — Bearer, Session + Secret, cookies with automatic refresh — but executes elsewhere (a gateway forwarding to another process, for instance) derives from `AppServer`, overrides `check_location()` for its own paths, calls `do_fetch()` from its method handlers and overrides `execute()`:

```cpp
void execute(const HttpRequest& req, std::shared_ptr<HttpConnection> conn,
             const ExecContext& ctx, std::string_view method,
             const std::string& payload, const ResultShaping& shaping) override;
```

It is called from every branch once authorisation is settled; on the refresh branch from inside the `daemon.refresh_token` callback, with `req` a copy that outlives the handler and `ctx.auth.token` the new access token. The response is deferred by then: answer through `conn`, and put `apply_refresh_cookies(resp, ctx)` on whatever you send. `ctx.auth_type == AuthType::none` is the unauthorised path.

A module answering in another shape (`problem+json`, say) also overrides `reply_refused(HttpResponse&, const Refusal&)`: every refusal this module produces itself — the six in `check_auth()` and the six in the refresh callback, which a derived class could not intercept otherwise — goes through it. `Refusal::kind` says what happened (`invalid`, `expired`, `refresh_failed`, `database`, `internal`), `status` and `message` say it in HTTP and in words; `body` carries the database's own payload for `Kind::database`, `path` the request's path (RFC 9457 `instance`). The base implementation keeps the v1 bodies and the `WWW-Authenticate` challenge exactly.

Installation
-

Follow the build and installation instructions for [Apostol (C++20)](https://github.com/apostoldevel/libapostol#build-and-installation).

[^crm]: **Apostol CRM** — a template project built on the [A-POST-OL](https://github.com/apostoldevel/libapostol) (C++20) and [PostgreSQL Framework for Backend Development](https://github.com/apostoldevel/db-platform) frameworks.
