#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "AppServer.hpp"
#include "apostol/application.hpp"

#include "apostol/base64.hpp"
#include "apostol/db_platform.hpp"
#include "apostol/http.hpp"
#include "apostol/http_utils.hpp"
#include "apostol/pg.hpp"
#include "apostol/pg_exec.hpp"
#include "apostol/pg_utils.hpp"

#include <algorithm>
#include <fmt/format.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace apostol
{

static constexpr const char* kCookieAT  = "__Secure-AT";
static constexpr const char* kCookieRT  = "__Secure-RT";
static constexpr const char* kCookieSAT = "__Secure-SAT";
static constexpr const char* kCookieSRT = "__Secure-SRT";
// See module-AuthServer for why the prefix is load-bearing: the value is the session
// code, trusted without a signature, and __Host- is what stops a sibling subdomain
// from planting one. Both modules must agree on the name — AuthServer mints the
// cookie, this one refreshes and clears it.
static constexpr const char* kCookieSID = "__Host-SID";
static constexpr int kCookieMaxAge      = 60 * 86400; // 60 days

// ─── Response shaping parameters ───────────────────────────────────────────
//
// Optional query parameters that control how PostgreSQL results are serialised:
//   result_object  — "true" wraps the result in {"result": ...}
//   result_format  — "object", "array", or "null" forces the serialisation format
//                    Paths containing "/list" default to "array".
//
struct ResultShaping
{
    std::string format;       // "", "object", "array", or "null"
    std::string object_name;  // "result" when result_object=true, else empty

    /// Parse and validate from request query parameters.
    /// Returns false and sets resp to 400 on invalid values.
    static bool parse(const HttpRequest& req, const std::string& path,
                      ResultShaping& out, HttpResponse& resp)
    {
        auto result_object = req.param("result_object");
        auto result_format = req.param("result_format");

        if (!result_object.empty()
            && result_object != "true" && result_object != "false") {
            reply_error(resp, HttpStatus::bad_request,
                        fmt::format("Invalid result_object: {}", result_object));
            return false;
        }

        if (!result_format.empty()
            && result_format != "object" && result_format != "array"
            && result_format != "null") {
            reply_error(resp, HttpStatus::bad_request,
                        fmt::format("Invalid result_format: {}", result_format));
            return false;
        }

        out.object_name = (result_object == "true") ? "result" : "";

        if (!result_format.empty()) {
            out.format = result_format;
        } else if (path.find("/list") != std::string::npos) {
            out.format = "array";
        }

        return true;
    }
};

// ─── Result processing (file-local) ────────────────────────────────────────
//
// Shared by all fetch variants. Handles:
//   - PG error → 500
//   - empty result → 200 with "{}"
//   - #raw → binary response (base64-decoded)
//   - PG-level error → appropriate HTTP status
//   - normal JSON → 200
//
static void process_result(HttpResponse& resp,
                           const std::vector<PgResult>& results,
                           const ResultShaping& shaping = {},
                           bool no_credentials = false)
{
    if (results.empty() || !results[0].ok()) {
        std::string err = results.empty()
            ? "no result"
            : (results[0].error_message()
                ? results[0].error_message() : "unknown error");
        reply_error(resp, HttpStatus::internal_server_error, err);
        return;
    }

    const auto& res = results[0];

    if (res.rows() == 0 || res.columns() == 0) {
        resp.set_status(HttpStatus::ok)
            .set_body(pg_result_to_json(res, shaping.format, shaping.object_name),
                      "application/json");
        return;
    }

    // Single row: check for #raw data and application-level errors
    if (res.rows() == 1) {
        const char* val = res.value(0, 0);
        std::string body = val ? val : "null";

        try {
            auto j = nlohmann::json::parse(body);

            // Check for raw binary data: {"#raw":{"#status":200,"#content_type":"...","#data":"base64..."}}
            if (j.contains("#raw") && j["#raw"].is_object()) {
                const auto& raw = j["#raw"];
                int status = raw.value("#status", 200);
                auto ct    = raw.value("#content_type", "application/octet-stream");
                auto data  = raw.value("#data", "");
                auto decoded = base64_decode(data);

                resp.set_status(status, "");
                resp.set_body(std::move(decoded), ct);
                return;
            }

            // Check for application-level error in PG response JSON
            std::string error_message;
            int error_code = check_pg_error(body, error_message);
            if (error_code != 0) {
                const auto status = error_code_to_status(error_code);

                // The body is the database's answer and is forwarded as it stands.
                // What was missing is the header: RFC 6750 §3 wants the challenge on
                // every 401 a resource server sends, and this path — an expired
                // token reported by db-platform rather than caught here — is one.
                // The scheme is advertised whatever the caller used to authenticate;
                // RFC 7235 §4.1 is about what the server accepts, not about what
                // this request tried.
                //
                // A request that carried no credentials at all gets the bare
                // challenge (§3.1: no error code) — the database's 401 to it
                // means "sign in", not "your token is bad". This is the answer
                // every unauthenticated call to a protected endpoint gets, and
                // the go-platform host already gives the bare form (T307).
                if (status == HttpStatus::unauthorized) {
                    if (no_credentials)
                        resp.set_header("WWW-Authenticate", "Bearer");
                    else
                        set_bearer_challenge(resp, "invalid_token", error_message);
                }

                resp.set_status(status)
                    .set_body(body, "application/json");
                return;
            }
        } catch (const nlohmann::json::exception&) {
            // Not valid JSON — fall through to pg_result_to_json
        }
    }

    // Use pg_result_to_json for all cases: handles multi-row, array wrapping, null values
    resp.set_status(HttpStatus::ok)
        .set_body(pg_result_to_json(res, shaping.format, shaping.object_name),
                  "application/json");
}

/// Clear auth cookies on sign-out (both user and service pairs).
static void clear_secure(HttpResponse& resp)
{
    resp.set_cookie(kCookieAT,  "", "/", -1, true, "None", true);
    resp.set_cookie(kCookieRT,  "", "/", -1, true, "None", true);
    resp.set_cookie(kCookieSAT, "", "/", -1, true, "None", true);
    resp.set_cookie(kCookieSRT, "", "/", -1, true, "None", true);
    // Attributes spelled out, not left to the defaults: a __Host- cookie is only
    // erased by a Set-Cookie carrying Secure and Path=/, and until this was written
    // the four-argument call cleared a differently-attributed cookie — that is, none.
    resp.set_cookie(kCookieSID, "", "/", -1, true, "Lax", true);

    // Transitional: the bare "SID" this cookie replaced. Nothing reads it any more,
    // so there is nothing to exploit — but a browser that signed in before the rename
    // would otherwise keep a live session code for the full 60 days after its owner
    // pressed "sign out", ready for any path that ever reads the bare name again.
    // Deletion matches on name and path only, so one line clears it whether it was
    // set with Secure (AuthServer) or without (this module, before the fix).
    // Remove after 2027-03: by then no cookie set under the old name is still alive.
    resp.set_cookie("SID", "", "/", -1);
}

// ─── Construction ───────────────────────────────────────────────────────────

AppServer::AppServer(Application& app)
    : log_(app.logger())
    , providers_(app.providers())
    , pool_(app.db_pool())
    , enabled_(true)
{
    if (auto* cfg = app.module_config("AppServer")) {
        if (cfg->contains("endpoints") && (*cfg)["endpoints"].is_array())
            for (auto& e : (*cfg)["endpoints"])
                if (e.is_string())
                    endpoints_.push_back(e.get<std::string>());
    }
    if (endpoints_.empty())
        endpoints_.push_back("/api/v1/*");

    if (auto* cfg = app.module_config("AppServer")) {
        if (auto it = cfg->find("guest_routes"); it != cfg->end()) {
            if (it->is_array()) {
                for (const auto& r : *it)
                    if (r.is_string())
                        guest_routes_.push_back(r.get<std::string>());
            } else {
                log_.warn("[AppServer] module.AppServer.guest_routes is not an array — ignored");
            }
        }
    }

    add_allowed_header("Authorization");
    add_allowed_header("Session");
    add_allowed_header("Secret");

    load_allowed_origins(providers_);
}

// ─── guest routes (T289) ────────────────────────────────────────────────────

bool AppServer::is_guest_route(std::string_view path) const
{
    return std::find(guest_routes_.begin(), guest_routes_.end(), path) != guest_routes_.end();
}

void AppServer::heartbeat(std::chrono::system_clock::time_point)
{
    // GatewayAPI derives from this module and reads the same section; only
    // AppServer itself serves guest routes, so only it holds a session for them.
    if (guest_routes_.empty() || name() != "AppServer")
        return;

    // The database closed the session a guest request ran under. The token
    // would otherwise be taken for good until it expires — up to a day of
    // every guest route answering 503. Mint a new one now.
    if (*guest_session_lost_) {
        *guest_session_lost_ = false;
        log_.warn("[AppServer] the guest routes' service session was closed by the "
                  "database — minting a new one");
        service_token_.invalidate();
    }

    const auto* svc = providers_.find_default("service");
    if (!svc) {
        if (service_token_.needs_refresh()) {
            log_.error("[AppServer] no \"service\" client in conf/oauth2: guest routes "
                       "will answer 503");
            service_token_.failed();
        }
        return;
    }

    std::string scope;
    for (const auto& sc : svc->scopes) {
        if (!scope.empty())
            scope += ' ';
        scope += sc;
    }

    // Cheap when the token is still good; see db_platform::refresh_service_token.
    db_platform::refresh_service_token(pool_, service_token_, log_, "[AppServer]",
                                       svc->client_id, svc->client_secret, scope,
                                       "AppServer/2.0", "127.0.0.1");
}

void AppServer::on_stop()
{
    if (guest_routes_.empty() || name() != "AppServer")
        return;
    db_platform::close_session(pool_, service_token_.token(), &log_, "[AppServer]");
    service_token_.invalidate();
}

// ─── check_location ─────────────────────────────────────────────────────────

bool AppServer::check_location(const HttpRequest& req) const
{
    return match_path(req.path, endpoints_);
}

// ─── init_methods ───────────────────────────────────────────────────────────

void AppServer::init_methods()
{
    add_method("GET",    [this](auto& req, auto& resp) { do_get(req, resp); });
    add_method("POST",   [this](auto& req, auto& resp) { do_post(req, resp); });
    add_method("PUT",    [this](auto& req, auto& resp) { do_put(req, resp); });
    add_method("PATCH",  [this](auto& req, auto& resp) { do_patch(req, resp); });
    add_method("DELETE", [this](auto& req, auto& resp) { do_delete(req, resp); });
}

// ─── Method handlers ────────────────────────────────────────────────────────

void AppServer::do_get(const HttpRequest& req, HttpResponse& resp)
{
    // Special routes (mirrors v1 DoGet)
    if (req.path == "/api/v1/ping") {
        resp.set_status(HttpStatus::ok)
            .set_body(R"({"error":{"code":200,"message":"OK"}})", "application/json");
        return;
    }

    if (req.path == "/api/v1/time") {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        resp.set_status(HttpStatus::ok)
            .set_body(fmt::format("{{\"serverTime\": {}}}", ms), "application/json");
        return;
    }

    do_fetch(req, resp, "GET");
}

void AppServer::do_post(const HttpRequest& req, HttpResponse& resp)
{
    do_fetch(req, resp, "POST");
}

void AppServer::do_put(const HttpRequest& req, HttpResponse& resp)
{
    do_fetch(req, resp, "PUT");
}

void AppServer::do_patch(const HttpRequest& req, HttpResponse& resp)
{
    do_fetch(req, resp, "PATCH");
}

void AppServer::do_delete(const HttpRequest& req, HttpResponse& resp)
{
    do_fetch(req, resp, "DELETE");
}

// ─── build_payload ──────────────────────────────────────────────────────────

std::string AppServer::build_payload(const HttpRequest& req)
{
    if (req.body.empty())
        return {};

    auto ct = req.content_type();
    std::transform(ct.begin(), ct.end(), ct.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (ct.find("application/json") != std::string::npos)
        return req.body;

    // Form data or other → convert to JSON
    return form_to_json(req.body);
}

// ─── do_fetch ───────────────────────────────────────────────────────────────

void AppServer::do_fetch(const HttpRequest& req, HttpResponse& resp,
                          std::string_view method)
{
    // Validate response shaping parameters before doing any work
    ResultShaping shaping;
    if (!ResultShaping::parse(req, req.path, shaping, resp))
        return;  // resp already set to 400

    auto payload = build_payload(req);

    if (payload_transformer_ && !payload.empty()) {
        try {
            payload = payload_transformer_(req, std::move(payload));
        } catch (const std::exception& e) {
            reply_error(resp, HttpStatus::bad_request,
                        fmt::format("Payload transform failed: {}", e.what()));
            return;
        }
    }

    Authorization auth;
    AuthType auth_type = AuthType::none;
    std::string refresh_token;
    bool is_service = false;

    int result = check_auth(req, resp, auth, auth_type, refresh_token, is_service);

    switch (result) {
        case 0:
        case 1: {
            // Authorisation settled (none, or as check_auth found it): the
            // step is the same, the context tells them apart.
            ExecContext ctx;
            ctx.auth       = std::move(auth);
            ctx.auth_type  = auth_type;
            ctx.is_service = is_service;

            resp.set_deferred(true);
            auto conn = std::static_pointer_cast<HttpConnection>(req.connection_ctx);
            execute(req, std::move(conn), ctx, method, payload, shaping);
            break;
        }
        case 2:
            token_refresh_and_fetch(req, resp, auth, refresh_token,
                                    method, payload, is_service, shaping);
            break;
        case -1:
            // resp already set (401/403)
            break;
    }
}

// ─── check_auth ─────────────────────────────────────────────────────────────

int AppServer::check_auth(const HttpRequest& req, HttpResponse& resp,
                           Authorization& auth, AuthType& auth_type,
                           std::string& refresh_token, bool& is_service)
{
    // Priority 1: Authorization header
    auto auth_header = req.header("Authorization");

    if (!auth_header.empty()) {
        auth = parse_authorization(auth_header);

        // "Authorization: Bearer " with nothing after it carries no credentials,
        // and RFC 6750 §3.1 answers a request without credentials with a bare
        // challenge, not invalid_token — it used to be "The access token is
        // malformed". Answered as a request without credentials (the Session
        // headers and cookies are not consulted on this path, as for any
        // Authorization header) — what the go-platform host does with it too.
        // Defensive: the parser trims the value, so from the wire it arrives
        // as "Bearer" and parse_authorization() already makes it no scheme.
        if (auth.schema == Authorization::Schema::bearer && auth.token.empty()) {
            auth_type = AuthType::none;
            return 0;
        }

        if (auth.schema == Authorization::Schema::bearer) {
            auth_type = AuthType::bearer;

            try {
                verify_jwt(auth.token, providers_);
                return 1;
            } catch (const JwtExpiredError&) {
                // 401, not 403. RFC 6750 §3.1 counts "expired" among the reasons
                // for invalid_token and asks for 401; 403 tells a client the token
                // was understood and the answer is still no, so it stops instead of
                // obtaining a new one. The cookie branch below has always answered
                // 401 to the same condition.
                reply_refused(resp, {Refusal::Kind::expired, HttpStatus::unauthorized, "invalid_token",
                                     "The access token has expired.", {}, req.path});
                return -1;
            } catch (const JwtVerificationError& e) {
                log_.warn("[AppServer] token verification failed: {}", e.what());
                reply_refused(resp, {Refusal::Kind::invalid, HttpStatus::unauthorized, "invalid_token",
                                     "The access token could not be verified.", {}, req.path});
                return -1;
            } catch (const std::exception& e) {
                // A token that is not a token at all. verify_jwt starts with
                // jwt::decode, outside its own try, so a value with the wrong number
                // of segments or broken base64 throws jwt-cpp's exception rather
                // than one of ours — and with nothing to catch it, it left this
                // handler, the connection was dropped, and the caller saw 502 from
                // the proxy. A malformed bearer token is the commonest of the three
                // cases in RFC 6750 §3.1 and the only one any stranger can produce.
                log_.warn("[AppServer] token rejected: {}", e.what());
                reply_refused(resp, {Refusal::Kind::invalid, HttpStatus::unauthorized, "invalid_token",
                                     "The access token is malformed.", {}, req.path});
                return -1;
            }
        }

        if (auth.schema == Authorization::Schema::basic) {
            auth_type = AuthType::basic_auth;
            return 1;
        }

        // Unknown schema
        return 0;
    }

    // Priority 2: Session + Secret headers
    auto session = req.header("Session");
    auto secret  = req.header("Secret");

    if (!session.empty() && !secret.empty()) {
        auth.schema   = Authorization::Schema::basic;
        auth.username = std::move(session);
        auth.password = std::move(secret);
        auth_type = AuthType::session;
        return 1;
    }

    // Priority 3: Cookie-based tokens (user or service, selected by X-Auth-Context)
    auto context = req.header("X-Auth-Context");
    is_service = (context == "service");

    auto access_token = req.cookie(is_service ? kCookieSAT : kCookieAT);

    if (!access_token.empty()) {
        auth.schema = Authorization::Schema::bearer;
        auth.token  = std::move(access_token);
        auth_type = AuthType::bearer;

        refresh_token = req.cookie(is_service ? kCookieSRT : kCookieRT);

        try {
            verify_jwt(auth.token, providers_);
            return 1;
        } catch (const JwtExpiredError&) {
            if (!refresh_token.empty())
                return 2;
            reply_refused(resp, {Refusal::Kind::expired, HttpStatus::unauthorized, "invalid_token",
                                     "The access token has expired.", {}, req.path});
            return -1;
        } catch (const JwtVerificationError& e) {
            log_.warn("[AppServer] cookie token verification failed: {}", e.what());
            reply_refused(resp, {Refusal::Kind::invalid, HttpStatus::unauthorized, "invalid_token",
                                     "The access token could not be verified.", {}, req.path});
            return -1;
        } catch (const std::exception& e) {
            // Same as the header branch: a cookie holding something that is not a
            // JWT threw past both handlers and dropped the connection.
            log_.warn("[AppServer] cookie token rejected: {}", e.what());
            reply_refused(resp, {Refusal::Kind::invalid, HttpStatus::unauthorized, "invalid_token",
                                     "The access token is malformed.", {}, req.path});
            return -1;
        }
    }

    // No auth at all
    auth_type = AuthType::none;
    return 0;
}

// ─── apply_refresh_cookies ──────────────────────────────────────────────────

void AppServer::apply_refresh_cookies(HttpResponse& resp, const ExecContext& ctx)
{
    if (!ctx.refreshed)
        return;

    auto at_name = ctx.is_service ? kCookieSAT : kCookieAT;
    auto rt_name = ctx.is_service ? kCookieSRT : kCookieRT;

    if (!ctx.auth.token.empty())
        resp.set_cookie(at_name, ctx.auth.token, "/",
                        kCookieMaxAge, true, "None", true);
    if (!ctx.new_refresh.empty())
        resp.set_cookie(rt_name, ctx.new_refresh, "/",
                        kCookieMaxAge, true, "None", true);
    // Same attributes AuthServer minted it with. On the defaults this call
    // replaced a Secure cookie with one without it on every token refresh,
    // quietly undoing the barrier a login had put up; under __Host- the
    // browser would now reject it instead.
    if (!ctx.session_id.empty() && !ctx.is_service)
        resp.set_cookie(kCookieSID, ctx.session_id, "/", kCookieMaxAge,
                        true, "Lax", true);
}

// ─── reply_refused ──────────────────────────────────────────────────────────

void AppServer::reply_refused(HttpResponse& resp, const Refusal& refusal)
{
    if (!refusal.body.empty()) {
        // The database refused: its payload is the answer, as it stands. The
        // challenge goes with a 401 whatever the caller used to authenticate
        // (RFC 7235 §4.1 is about what the server accepts).
        if (refusal.status == HttpStatus::unauthorized && !refusal.error.empty())
            set_bearer_challenge(resp, refusal.error, refusal.message);
        resp.set_status(refusal.status)
            .set_body(std::string(refusal.body), "application/json");
        return;
    }
    if (!refusal.error.empty()) {
        reply_bearer_error(resp, refusal.status, refusal.error, refusal.message);
        return;
    }
    reply_error(resp, refusal.status, refusal.message);
}

// ─── execute ────────────────────────────────────────────────────────────────

void AppServer::execute(const HttpRequest& req, std::shared_ptr<HttpConnection> conn,
                        const ExecContext& ctx, std::string_view method,
                        const std::string& payload, const ResultShaping& shaping)
{
    auto method_q  = pq_quote_literal(method);
    auto path_q    = pq_quote_literal(req.path);
    auto payload_q = payload.empty() ? std::string("null")
                                     : pq_quote_literal(payload);
    auto agent_q   = pq_quote_literal(get_user_agent(req));
    auto host_q    = pq_quote_literal(get_real_ip(req));

    std::string sql;

    if (ctx.auth_type == AuthType::none && is_guest_route(req.path)) {
        // A guest route: no credentials, and none needed from the caller —
        // the module asks on its own behalf, as AuthServer does for
        // /oauth2/identifier. The browser used to mint that token itself by
        // client_credentials, which made the service client public (T289).
        if (!service_token_.valid()) {
            HttpResponse r;
            reply_error(r, HttpStatus::service_unavailable,
                        "The service account is not available.");
            r.set_header("Retry-After", "1");
            conn->send_response(r);
            return;
        }
        sql = fmt::format(
            "SELECT * FROM daemon.fetch({}, {}, {}, {}::jsonb, {}, {})",
            pq_quote_literal(service_token_.token()), method_q, path_q,
            payload_q, agent_q, host_q);
    } else if (ctx.auth_type == AuthType::none) {
        // daemon.unauthorized_fetch(method, path, payload, agent, host)
        sql = fmt::format(
            "SELECT * FROM daemon.unauthorized_fetch({}, {}, {}::jsonb, {}, {})",
            method_q, path_q, payload_q, agent_q, host_q);
    } else if (ctx.auth.schema == Authorization::Schema::bearer) {
        // daemon.fetch(token, method, path, payload, agent, host)
        sql = fmt::format(
            "SELECT * FROM daemon.fetch({}, {}, {}, {}::jsonb, {}, {})",
            pq_quote_literal(ctx.auth.token), method_q, path_q,
            payload_q, agent_q, host_q);
    } else if (ctx.auth_type == AuthType::session) {
        // daemon.session_fetch(session, secret, method, path, payload, agent, host)
        sql = fmt::format(
            "SELECT * FROM daemon.session_fetch({}, {}, {}, {}, {}::jsonb, {}, {})",
            pq_quote_literal(ctx.auth.username), pq_quote_literal(ctx.auth.password),
            method_q, path_q, payload_q, agent_q, host_q);
    } else {
        // daemon.authorized_fetch(username, password, method, path, payload, agent, host)
        sql = fmt::format(
            "SELECT * FROM daemon.authorized_fetch({}, {}, {}, {}, {}::jsonb, {}, {})",
            pq_quote_literal(ctx.auth.username), pq_quote_literal(ctx.auth.password),
            method_q, path_q, payload_q, agent_q, host_q);
    }

    auto req_path = req.path;
    const bool guest = ctx.auth_type == AuthType::none && is_guest_route(req.path);
    auto guest_session_lost = guest_session_lost_;

    // quiet: depending on the branch above the statement carries an access token,
    // a session code with its secret, or a username and password — or, on the
    // unauthorised path, the payload IS the credential: /sign/in, /sign/up and
    // /authenticate all arrive through daemon.unauthorized_fetch with the user's
    // password in clear text (see rest.sql's /sign/in branch). PgPool logs
    // statement text, and a dedicated postgres.log keeps it at debug — this runs
    // on every API request, so it would be a continuous credential leak into
    // that file. AddApiLog strips `password` before writing db.api_log; recording
    // it here would contradict the platform's own intent.
    // No `this` in the capture: nothing below needs the module, and a result
    // callback should not have to know how long the module lives.
    pool_.execute(std::move(sql),
        [conn, req_path, shaping, ctx, guest, guest_session_lost](std::vector<PgResult> results) {
            HttpResponse r;
            r.set_header("Content-Type", "application/json");
            process_result(r, results, shaping, ctx.auth_type == AuthType::none);

            // A guest route answered 401: not the guest's credentials — it
            // sent none — but the module's service session, which the
            // database has closed (a rate limiter signs the calling session
            // out, and here every guest shares one). Say "try again" rather
            // than "sign in", and have heartbeat() mint a new session.
            if (guest && r.status_code() == 401) {
                *guest_session_lost = true;
                r.clear();
                reply_error(r, HttpStatus::service_unavailable,
                            "The service account is not available.");
                r.set_header("Retry-After", "1");
            }

            // Sign-out wins over the refresh, and this is the whole of the
            // rule: a request that ends the session never leaves credentials
            // behind, however it got itself authorised on the way in.
            //
            // It used to be the other way round. The clearing was skipped when
            // the request had refreshed its token, and apply_refresh_cookies()
            // then minted a fresh pair with a sixty-day Max-Age — on the very
            // answer that had just closed the session in the database. An
            // access token lives an hour, so a sign-out pressed later than that
            // took this branch as a matter of course rather than as an edge
            // case: on a shared terminal — a ship's bridge console is the case
            // that found this — "log out" left a full, live-looking cookie set
            // on the machine. The session behind it was dead, so nobody got in
            // with it; what failed is the promise the button makes, which is
            // that the credentials are gone from here.
            const bool signing_out = req_path.find("/sign/out") != std::string::npos;
            if (signing_out)
                clear_secure(r);
            else
                apply_refresh_cookies(r, ctx);
            conn->send_response(r);
        },
        [conn](std::string_view error) {
            HttpResponse r;
            reply_error(r, HttpStatus::internal_server_error, error);
            conn->send_response(r);
        },
        /*quiet=*/true);
}

// ─── token_refresh_and_fetch ────────────────────────────────────────────────

void AppServer::token_refresh_and_fetch(const HttpRequest& req, HttpResponse& resp,
                                         const Authorization& auth,
                                         const std::string& refresh_token,
                                         std::string_view method,
                                         const std::string& payload,
                                         bool is_service,
                                         const ResultShaping& shaping)
{
    // Step 1: refresh the token via daemon.refresh_token(token, refresh_token)
    auto refresh_sql = fmt::format(
        "SELECT daemon.refresh_token({}, {})",
        pq_quote_literal(auth.token),
        pq_quote_literal(refresh_token));

    // The request itself is a local of HttpConnection::on_readable and is gone
    // once this handler returns; the chained execute() wants the whole of it
    // (an override forwards headers and body). A copy, on this branch only —
    // it is the rare one — with connection_ctx carried along.
    auto req_copy    = req;
    auto method_str  = std::string(method);
    auto payload_str = payload;

    ExecContext ctx;
    ctx.auth       = auth;          // token replaced by the refreshed one below
    ctx.auth_type  = AuthType::bearer;
    ctx.is_service = is_service;
    ctx.refreshed  = true;

    // quiet: the statement carries BOTH the access token and the refresh token.
    // The refresh token is the longest-lived credential in the system — new
    // access tokens are minted from it and revoking it goes a separate way —
    // and this runs on every token refresh. The neighbours on both sides are
    // already quiet; this one looked like a plumbing step rather than a query.
    exec_sql(pool_, req, resp, std::move(refresh_sql),
        [this, req_copy = std::move(req_copy), method_str, payload_str, ctx, shaping]
        (std::shared_ptr<HttpConnection> conn,
         std::vector<PgResult> results) mutable {

            HttpResponse r;
            r.set_header("Content-Type", "application/json");

            if (results.empty() || !results[0].ok()) {
                std::string err = results.empty()
                    ? "no result"
                    : (results[0].error_message()
                        ? results[0].error_message() : "unknown error");
                reply_refused(r, {Refusal::Kind::internal, HttpStatus::internal_server_error, {}, err, {}, req_copy.path});
                conn->send_response(r);
                return;
            }

            // An answer daemon.refresh_token never gives — no row, a null, a JSON
            // without access_token and without an error — is this side failing,
            // not the token: 500, not 401. As 401 token-expired / ERR-401-008 it
            // sent the client to sign in again instead of retrying.
            const auto& res = results[0];
            if (res.rows() == 0 || res.columns() == 0) {
                reply_refused(r, {Refusal::Kind::internal, HttpStatus::internal_server_error, {},
                              "Token refresh failed.", {}, req_copy.path});
                conn->send_response(r);
                return;
            }

            const char* val = res.value(0, 0);
            if (!val) {
                reply_refused(r, {Refusal::Kind::internal, HttpStatus::internal_server_error, {},
                              "Token refresh returned null.", {}, req_copy.path});
                conn->send_response(r);
                return;
            }

            std::string refresh_body(val);

            try {
                auto refresh_result = nlohmann::json::parse(refresh_body);

                // Check for error in refresh result
                std::string error_message;
                int error_code = check_pg_error(refresh_body, error_message);
                if (error_code != 0) {
                    auto status = error_code_to_status(error_code);

                    // A refresh the database refuses (4xx) leaves the caller with a
                    // dead pair, whatever code it said: "Malformed refresh token." is
                    // 400 invalid_grant, a spent or closed refresh. It used to go out
                    // as that 400; a client re-authenticates on 401 only, so it kept
                    // polling with the same cookies and got the same 400 on every
                    // request until it signed in again by hand. 401 invalid_token
                    // (RFC 6750 §3.1). A 5xx is this side failing, not a refusal:
                    // it passes through.
                    //
                    // The cookies are NOT erased here, on purpose. This request may be
                    // the late one of a pair: its neighbour has already rotated the
                    // refresh and the browser holds the live pair from that answer. A
                    // Max-Age=0 on this answer would delete it and sign out a working
                    // session. A dead pair costs nothing to leave: the next request
                    // gets the same 401, and a sign-in overwrites it.
                    if (static_cast<int>(status) < 500)
                        status = HttpStatus::unauthorized;

                    reply_refused(r, {Refusal::Kind::database, status,
                                      status == HttpStatus::unauthorized ? "invalid_token" : "",
                                      error_message, refresh_body, req_copy.path});
                    conn->send_response(r);
                    return;
                }

                // Extract new access token
                std::string new_token;
                if (refresh_result.contains("access_token"))
                    new_token = refresh_result["access_token"].get<std::string>();

                if (new_token.empty()) {
                    reply_refused(r, {Refusal::Kind::internal, HttpStatus::internal_server_error, {},
                              "No access_token in refresh response.", {}, req_copy.path});
                    conn->send_response(r);
                    return;
                }

                // Extract optional refresh token and session
                if (refresh_result.contains("refresh_token"))
                    ctx.new_refresh = refresh_result["refresh_token"].get<std::string>();
                if (refresh_result.contains("session"))
                    ctx.session_id = refresh_result["session"].get<std::string>();

                // Step 2: the request itself, with the refreshed token in force.
                // The cookies for the new pair go on the final response —
                // apply_refresh_cookies, inside execute().
                ctx.auth.token = std::move(new_token);
                execute(req_copy, conn, ctx, method_str, payload_str, shaping);

            } catch (const nlohmann::json::exception& e) {
                const auto msg = fmt::format("Failed to parse refresh response: {}", e.what());
                reply_refused(r, {Refusal::Kind::internal, HttpStatus::internal_server_error, {}, msg, {}, req_copy.path});
                conn->send_response(r);
            }
        },
        /*quiet=*/true);
}

} // namespace apostol

#endif // defined(WITH_POSTGRESQL) && defined(WITH_SSL)
