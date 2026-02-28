[![ru](https://img.shields.io/badge/lang-ru-green.svg)](README.ru-RU.md)

App Server
-

**Module** for [Apostol](https://github.com/apostoldevel/apostol) + [db-platform](https://github.com/apostoldevel/db-platform) — **Apostol CRM**[^crm].

Description
-

**App Server** is a C++ HTTP/RESTful server module for the [Apostol](https://github.com/apostoldevel/apostol) framework. It runs inside Apostol worker processes and handles all incoming HTTP requests routed to the `/api/` path prefix.

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

Installation
-

Follow the build and installation instructions for [Apostol](https://github.com/apostoldevel/apostol#building-and-installation).

[^crm]: **Apostol CRM** is an abstract term, not a standalone product. It refers to any project that uses both the [Apostol](https://github.com/apostoldevel/apostol) C++ framework and [db-platform](https://github.com/apostoldevel/db-platform) together through purpose-built modules and processes. Each framework can be used independently; combined, they form a full-stack backend platform.
