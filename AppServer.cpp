#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "AppServer.hpp"
#include "apostol/application.hpp"

#include "apostol/base64.hpp"
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

// ─── Result processing (file-local) ────────────────────────────────────────
//
// Shared by all fetch variants. Handles:
//   - PG error → 500
//   - empty result → 204
//   - #raw → binary response (base64-decoded)
//   - PG-level error → appropriate HTTP status
//   - normal JSON → 200
//
static void process_result(HttpResponse& resp,
                           const std::vector<PgResult>& results)
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
        resp.set_status(HttpStatus::no_content);
        return;
    }

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
            resp.set_status(error_code_to_status(error_code))
                .set_body(body, "application/json");
        } else {
            resp.set_status(HttpStatus::ok)
                .set_body(body, "application/json");
        }
    } catch (const nlohmann::json::exception&) {
        // Not valid JSON — return as-is
        resp.set_status(HttpStatus::ok)
            .set_body(body, "application/json");
    }
}

/// PgResultHandler that processes result and sends response.
static void on_fetch_result(std::shared_ptr<HttpConnection> conn,
                            std::vector<PgResult> results)
{
    HttpResponse r;
    r.set_header("Content-Type", "application/json");
    process_result(r, results);
    conn->send_response(r);
}

// ─── Construction ───────────────────────────────────────────────────────────

AppServer::AppServer(Application& app)
    : pool_(app.db_pool())
    , loop_(app.worker_loop())
    , providers_(app.providers())
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

    add_allowed_header("Authorization");
    add_allowed_header("Session");
    add_allowed_header("Secret");

    load_allowed_origins(providers_);
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
        resp.set_status(HttpStatus::ok).set_body("{}", "application/json");
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
    auto payload = build_payload(req);

    Authorization auth;
    AuthType auth_type = AuthType::none;
    std::string refresh_token;

    int result = check_auth(req, resp, auth, auth_type, refresh_token);

    switch (result) {
        case 0:
            unauthorized_fetch(req, resp, method, payload);
            break;
        case 1:
            authorized_fetch(req, resp, auth, auth_type, method, payload);
            break;
        case 2:
            token_refresh_and_fetch(req, resp, auth, refresh_token,
                                    method, payload);
            break;
        case -1:
            // resp already set (401/403)
            break;
    }
}

// ─── check_auth ─────────────────────────────────────────────────────────────

int AppServer::check_auth(const HttpRequest& req, HttpResponse& resp,
                           Authorization& auth, AuthType& auth_type,
                           std::string& refresh_token)
{
    // Priority 1: Authorization header
    auto auth_header = req.header("Authorization");

    if (!auth_header.empty()) {
        auth = parse_authorization(auth_header);

        if (auth.schema == Authorization::Schema::bearer) {
            auth_type = AuthType::bearer;

            try {
                verify_jwt(auth.token, providers_);
                return 1;
            } catch (const JwtExpiredError&) {
                reply_error(resp, HttpStatus::forbidden, "Token expired.");
                return -1;
            } catch (const JwtVerificationError& e) {
                reply_error(resp, HttpStatus::unauthorized, e.what());
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

    // Priority 3: Cookie-based tokens
    auto access_token = req.cookie("__Secure-AT");

    if (!access_token.empty()) {
        auth.schema = Authorization::Schema::bearer;
        auth.token  = std::move(access_token);
        auth_type = AuthType::bearer;

        refresh_token = url_decode(req.cookie("__Secure-RT"));

        try {
            verify_jwt(auth.token, providers_);
            return 1;
        } catch (const JwtExpiredError&) {
            if (!refresh_token.empty())
                return 2;
            reply_error(resp, HttpStatus::unauthorized, "Token expired.");
            return -1;
        } catch (const JwtVerificationError& e) {
            reply_error(resp, HttpStatus::unauthorized, e.what());
            return -1;
        }
    }

    // No auth at all
    auth_type = AuthType::none;
    return 0;
}

// ─── unauthorized_fetch ─────────────────────────────────────────────────────

void AppServer::unauthorized_fetch(const HttpRequest& req, HttpResponse& resp,
                                    std::string_view method,
                                    const std::string& payload)
{
    auto method_q  = pq_quote_literal(method);
    auto path_q    = pq_quote_literal(req.path);
    auto payload_q = payload.empty() ? std::string("null")
                                     : pq_quote_literal(payload);
    auto agent_q   = pq_quote_literal(get_user_agent(req));
    auto host_q    = pq_quote_literal(get_real_ip(req));

    auto sql = fmt::format(
        "SELECT * FROM daemon.unauthorized_fetch({}, {}, {}::jsonb, {}, {})",
        method_q, path_q, payload_q, agent_q, host_q);

    exec_sql(pool_, req, resp, std::move(sql), on_fetch_result);
}

// ─── authorized_fetch ───────────────────────────────────────────────────────

void AppServer::authorized_fetch(const HttpRequest& req, HttpResponse& resp,
                                  const Authorization& auth, AuthType auth_type,
                                  std::string_view method,
                                  const std::string& payload)
{
    auto method_q  = pq_quote_literal(method);
    auto path_q    = pq_quote_literal(req.path);
    auto payload_q = payload.empty() ? std::string("null")
                                     : pq_quote_literal(payload);
    auto agent_q   = pq_quote_literal(get_user_agent(req));
    auto host_q    = pq_quote_literal(get_real_ip(req));

    std::string sql;

    if (auth.schema == Authorization::Schema::bearer) {
        // daemon.fetch(token, method, path, payload, agent, host)
        sql = fmt::format(
            "SELECT * FROM daemon.fetch({}, {}, {}, {}::jsonb, {}, {})",
            pq_quote_literal(auth.token), method_q, path_q,
            payload_q, agent_q, host_q);
    } else if (auth_type == AuthType::session) {
        // daemon.session_fetch(session, secret, method, path, payload, agent, host)
        sql = fmt::format(
            "SELECT * FROM daemon.session_fetch({}, {}, {}, {}, {}::jsonb, {}, {})",
            pq_quote_literal(auth.username), pq_quote_literal(auth.password),
            method_q, path_q, payload_q, agent_q, host_q);
    } else {
        // daemon.authorized_fetch(username, password, method, path, payload, agent, host)
        sql = fmt::format(
            "SELECT * FROM daemon.authorized_fetch({}, {}, {}, {}, {}::jsonb, {}, {})",
            pq_quote_literal(auth.username), pq_quote_literal(auth.password),
            method_q, path_q, payload_q, agent_q, host_q);
    }

    exec_sql(pool_, req, resp, std::move(sql), on_fetch_result);
}

// ─── token_refresh_and_fetch ────────────────────────────────────────────────

void AppServer::token_refresh_and_fetch(const HttpRequest& req, HttpResponse& resp,
                                         const Authorization& auth,
                                         const std::string& refresh_token,
                                         std::string_view method,
                                         const std::string& payload)
{
    // Step 1: refresh the token via daemon.refresh_token(token, refresh_token)
    auto refresh_sql = fmt::format(
        "SELECT daemon.refresh_token({}, {})",
        pq_quote_literal(auth.token),
        pq_quote_literal(refresh_token));

    // Capture values needed for the chained second query
    auto method_str  = std::string(method);
    auto payload_str = payload;
    auto path_str    = req.path;
    auto agent_str   = get_user_agent(req);
    auto host_str    = get_real_ip(req);

    auto pool_ptr = &pool_;

    exec_sql(pool_, req, resp, std::move(refresh_sql),
        [pool_ptr, method_str, payload_str, path_str, agent_str, host_str]
        (std::shared_ptr<HttpConnection> conn,
         std::vector<PgResult> results) {

            HttpResponse r;
            r.set_header("Content-Type", "application/json");

            if (results.empty() || !results[0].ok()) {
                std::string err = results.empty()
                    ? "no result"
                    : (results[0].error_message()
                        ? results[0].error_message() : "unknown error");
                reply_error(r, HttpStatus::internal_server_error, err);
                conn->send_response(r);
                return;
            }

            const auto& res = results[0];
            if (res.rows() == 0 || res.columns() == 0) {
                reply_error(r, HttpStatus::unauthorized, "Token refresh failed.");
                conn->send_response(r);
                return;
            }

            const char* val = res.value(0, 0);
            if (!val) {
                reply_error(r, HttpStatus::unauthorized,
                            "Token refresh returned null.");
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
                    r.set_status(error_code_to_status(error_code))
                     .set_body(refresh_body, "application/json");
                    conn->send_response(r);
                    return;
                }

                // Extract new access token
                std::string new_token;
                if (refresh_result.contains("access_token"))
                    new_token = refresh_result["access_token"].get<std::string>();

                if (new_token.empty()) {
                    reply_error(r, HttpStatus::unauthorized,
                                "No access_token in refresh response.");
                    conn->send_response(r);
                    return;
                }

                // Extract optional refresh token and session
                std::string new_refresh;
                std::string session_id;
                if (refresh_result.contains("refresh_token"))
                    new_refresh = refresh_result["refresh_token"].get<std::string>();
                if (refresh_result.contains("session"))
                    session_id = refresh_result["session"].get<std::string>();

                // Step 2: execute the actual fetch with the refreshed token
                auto method_q  = pq_quote_literal(method_str);
                auto path_q    = pq_quote_literal(path_str);
                auto payload_q = payload_str.empty() ? std::string("null")
                                                     : pq_quote_literal(payload_str);
                auto agent_q   = pq_quote_literal(agent_str);
                auto host_q    = pq_quote_literal(host_str);
                auto token_q   = pq_quote_literal(new_token);

                auto fetch_sql = fmt::format(
                    "SELECT * FROM daemon.fetch({}, {}, {}, {}::jsonb, {}, {})",
                    token_q, method_q, path_q, payload_q, agent_q, host_q);

                // Chain: second PG query using the refreshed token
                pool_ptr->execute(std::move(fetch_sql),
                    [conn, new_token, new_refresh, session_id]
                    (std::vector<PgResult> results2) {
                        HttpResponse r2;
                        r2.set_header("Content-Type", "application/json");

                        // Set secure cookies with refreshed tokens
                        if (!new_token.empty())
                            r2.set_cookie("__Secure-AT", new_token, "/",
                                         60 * 86400, true, "None", true);
                        if (!new_refresh.empty())
                            r2.set_cookie("__Secure-RT", new_refresh, "/",
                                         60 * 86400, true, "None", true);
                        if (!session_id.empty())
                            r2.set_cookie("SID", session_id, "/", 60 * 86400);

                        process_result(r2, results2);
                        conn->send_response(r2);
                    },
                    // on_exception for chained fetch
                    [conn](std::string_view error) {
                        HttpResponse r2;
                        reply_error(r2, HttpStatus::internal_server_error, error);
                        conn->send_response(r2);
                    });

            } catch (const nlohmann::json::exception& e) {
                reply_error(r, HttpStatus::internal_server_error,
                            fmt::format("Failed to parse refresh response: {}",
                                        e.what()));
                conn->send_response(r);
            }
        });
}

} // namespace apostol

#endif // defined(WITH_POSTGRESQL) && defined(WITH_SSL)
