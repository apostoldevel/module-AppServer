[![ru](https://img.shields.io/badge/lang-ru-green.svg)](https://github.com/apostoldevel/module-AppServer/blob/master/README.ru-RU.md)

App Server
-

**Module** for [Apostol](https://github.com/apostoldevel/apostol).

Description
-

**App Server** is a C++ HTTP/RESTful server module for the [Apostol](https://github.com/apostoldevel/apostol) framework. It runs inside Apostol worker processes and handles all incoming HTTP requests routed to the `/api/` path prefix.

Key characteristics:

* Written in C++14 using an asynchronous, non-blocking I/O model based on the **epoll** API — suitable for high-throughput, low-latency deployments.
* Connects directly to **PostgreSQL** via the `libpq` library. Every API request is dispatched to a PL/pgSQL function in the database; all business logic lives in the database, not in the module itself.
* Implements **REST** (Representational State Transfer) conventions for remote procedure calls over HTTP.
* Supports two authentication methods: **Bearer JWT** token and **HMAC-SHA256** request signature.
* Response format is always `application/json`.
* Built-in endpoints (`/ping`, `/time`) require no database interaction and are handled entirely in C++. All other endpoints are forwarded to the PostgreSQL `daemon` schema functions.

### How it fits into Apostol

Apostol runs a master process that forks N worker processes. Each worker loads a set of modules. `CAppServer` is one such module — it registers itself as the handler for any request whose path starts with `/api/`. When a matching request arrives:

1. The worker's event loop (epoll) accepts the connection and reads the HTTP request.
2. `CAppServer` inspects the `Authorization` header or signature headers to determine the authentication context.
3. It constructs a parameterised SQL call (`daemon.fetch`, `daemon.unauthorized_fetch`, or `daemon.signed_fetch`) and submits it to the PostgreSQL connection pool asynchronously.
4. When the query result arrives, the module serialises it as JSON and sends the HTTP reply.

The module also manages a short-lived response cache (1-minute TTL, paths listed in `cache.conf`) and reloads OAuth2 provider public keys from `certs/` every 30 minutes via its `Heartbeat` method.

Installation
-

Follow the build and installation instructions for [Apostol](https://github.com/apostoldevel/apostol#building-and-installation).

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
* The module accepts `GET`, `POST`, and `OPTIONS`. All other HTTP methods return `405 Method Not Allowed`.

### Response shaping (optional query parameters)

Two optional query parameters influence how PostgreSQL query results are serialised:

| Parameter | Allowed values | Effect |
|-----------|----------------|--------|
| `result_object` | `true`, `false` | When `true`, wraps the result in `{"result": ...}` |
| `result_format` | `object`, `array`, `null` | Forces the JSON serialisation format of the result set. Paths containing `/list` default to `array`. |

API Access
-

Access requires either a **Bearer access token** or an **HMAC-SHA256 request signature**.

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

### HMAC-SHA256 signature

Instead of an `Authorization` header, a request may be authenticated using an HMAC-SHA256 signature. Three HTTP headers carry the authentication data:

| Header | Description |
|--------|-------------|
| `Session` | Session key (40-character hex string) |
| `Nonce` | Current time in **microseconds** (Unix epoch × 1000) |
| `Signature` | HMAC-SHA256 hex digest |

The signature is computed over the concatenation of:

```
<path><nonce><body>
```

Where `<body>` is the JSON-stringified request body, or the string `"null"` if there is no body.

The receive window defaults to **5000 milliseconds**; pass `?receive_window=<ms>` to override it.

**This feature is only active when the module is compiled with `CALL_SIGNATURE_FETCH` defined.**

---

<details>
  <summary>JavaScript example — signature without a request body</summary>

```javascript
// CryptoJS - Standard JavaScript cryptography library

const body = null;

const Session = localStorage.getItem('Session'); // efa885ebde1baa991a3c798fc1141f6bec92fc90
const Secret  = localStorage.getItem('Secret');  // y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC

const Path      = '/whoami';
const Nonce     = (Date.now() * 1000).toString(); // 1589998352818000
const Body      = JSON.stringify(body);           // "null"  (string, not null)

const sigData   = `${Path}${Nonce}${Body}`;       // /whoami1589998352818000null

const Signature = CryptoJS.HmacSHA256(sigData, Secret).toString();
// 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1

let headers = new Headers();
headers.append('Session',      Session);
headers.append('Nonce',        Nonce);
headers.append('Signature',    Signature);
headers.append('Content-Type', 'application/json');

const init = { method: 'POST', headers, body: Body, mode: 'cors' };

fetch(`/api/v1${Path}`, init)
    .then(r => r.json())
    .then(json => console.log(json))
    .catch(e  => console.log(e.message));
```

Verify with openssl:

```shell
echo -n "/whoami1589998352818000null" | \
  openssl sha256 -hmac "y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC"
(stdin)= 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1
```

curl:

```shell
curl -X POST \
     -H "Session: efa885ebde1baa991a3c798fc1141f6bec92fc90" \
     -H "Nonce: 1589998352818000" \
     -H "Signature: 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1" \
     http://localhost:8080/api/v1/whoami
```

HTTP request:

```http
POST /api/v1/whoami HTTP/1.1
Host: localhost:8080
Session: efa885ebde1baa991a3c798fc1141f6bec92fc90
Nonce: 1589998352818000
Signature: 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1
```

</details>

<details>
  <summary>JavaScript example — signature with a JSON request body</summary>

```javascript
// CryptoJS - Standard JavaScript cryptography library

const body = {
  classcode : 'client',
  statecode : 'enabled',
  actioncode: 'invite'
};

const Session = localStorage.getItem('Session'); // efa885ebde1baa991a3c798fc1141f6bec92fc90
const Secret  = localStorage.getItem('Secret');  // y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC

const Path      = '/method/get';
const Nonce     = (Date.now() * 1000).toString(); // 1589998352902000
const Body      = JSON.stringify(body);

// /method/get1589998352902000{"classcode":"client","statecode":"enabled","actioncode":"invite"}
const sigData   = `${Path}${Nonce}${Body}`;

const Signature = CryptoJS.HmacSHA256(sigData, Secret).toString();
// 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b

let headers = new Headers();
headers.append('Session',      Session);
headers.append('Nonce',        Nonce);
headers.append('Signature',    Signature);
headers.append('Content-Type', 'application/json');

const init = { method: 'POST', headers, body: Body, mode: 'cors' };

fetch(`/api/v1${Path}`, init)
    .then(r => r.json())
    .then(json => console.log(json))
    .catch(e  => console.log(e.message));
```

Verify with openssl:

```shell
echo -n "/method/get1589998352902000{\"classcode\":\"client\",\"statecode\":\"enabled\",\"actioncode\":\"invite\"}" | \
  openssl sha256 -hmac "y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC"
(stdin)= 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b
```

curl:

```shell
curl -X POST \
     -H "Session: efa885ebde1baa991a3c798fc1141f6bec92fc90" \
     -H "Nonce: 1589998352902000" \
     -H "Signature: 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b" \
     -d '{"classcode":"client","statecode":"enabled","actioncode":"invite"}' \
     http://localhost:8080/api/v1/method/get
```

HTTP request:

```http
POST /api/v1/method/get HTTP/1.1
Host: localhost:8080
Session: efa885ebde1baa991a3c798fc1141f6bec92fc90
Nonce: 1589998352902000
Signature: 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b

{"classcode":"client","statecode":"enabled","actioncode":"invite"}
```

</details>

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
| HMAC-SHA256 signature | `daemon.signed_fetch(method, path, payload, session, nonce, signature, agent, host, window)` |

The full set of application endpoints is therefore defined entirely in the project's database, in the `daemon` schema PL/pgSQL functions. **See your project's repository for endpoint documentation.**
