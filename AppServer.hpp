#pragma once

#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "apostol/http.hpp"
#include "apostol/apostol_module.hpp"
#include "apostol/jwt.hpp"
#include "apostol/oauth_providers.hpp"
#include "apostol/pg.hpp"

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace apostol
{

class Application;
struct ResultShaping;

// ─── AppServer ──────────────────────────────────────────────────────────────
//
// Worker module that routes REST requests through auth-aware PostgreSQL
// functions (daemon.fetch, daemon.unauthorized_fetch, etc.).
//
// Unlike PGHTTP (which calls "http.get/post/..." without auth), AppServer
// handles Bearer JWT, Basic auth, Session+Secret headers, and cookie-based
// auth. It is the primary REST API module for Apostol CRM projects.
//
// Mirrors v1 CAppServer from src/modules/Workers/AppServer/.
//
// Open for derivation: a module that keeps this authorisation — check_auth,
// the cookie token refresh — but executes the request elsewhere (a gateway
// forwarding to another process) overrides execute() and nothing else.
//
class AppServer : public ApostolModule
{
public:
    explicit AppServer(Application& app);

    std::string_view name() const override { return "AppServer"; }
    bool enabled() const override { return enabled_; }
    bool check_location(const HttpRequest& req) const override;
    void heartbeat(std::chrono::system_clock::time_point) override {}

    // ── Payload transform hook ──────────────────────────────────────────────
    //
    // Optional transform applied to the request payload (the JSON body produced
    // by build_payload) before it is dispatched to PostgreSQL. Generic by design
    // — e.g. a transformer that downscales base64 images embedded in the body.
    // Receives the request (for path/headers) and the current payload, and
    // returns the payload to dispatch. Transformers should not throw; if one
    // does, do_fetch maps the failure to HTTP 400.
    using PayloadTransformer =
        std::function<std::string(const HttpRequest&, std::string)>;

    void set_payload_transformer(PayloadTransformer fn)
    {
        payload_transformer_ = std::move(fn);
    }

protected:
    void init_methods() override;

    // ── Auth type ───────────────────────────────────────────────────────────

    enum class AuthType { none, bearer, session, basic_auth };

    // ── What execute() receives once authorisation is settled ──────────────

    struct ExecContext
    {
        // What the call is authorised with. auth.token is the access token in
        // force — after a refresh, the NEW one. On the unauthorised path the
        // schema is none and the token empty. The whole Authorization, not
        // just the token: session_fetch/authorized_fetch need username and
        // password.
        Authorization auth;
        AuthType      auth_type{AuthType::none};
        bool          is_service{false};   // X-Auth-Context: service

        // Set only after daemon.refresh_token succeeded: what the final
        // response must carry as cookies (apply_refresh_cookies). The new
        // access token is auth.token.
        bool          refreshed{false};
        std::string   new_refresh;
        std::string   session_id;
    };

    // ── Main dispatch ───────────────────────────────────────────────────────
    //
    // Validates shaping parameters, builds the payload, decides authorisation
    // (check_auth) and hands the request to execute(). A derived module with
    // its own method handlers calls this from them.
    void do_fetch(const HttpRequest& req, HttpResponse& resp,
                  std::string_view method);

    // ── Authorization ───────────────────────────────────────────────────────
    //
    //  Returns:  1 = ok (authorized)
    //            0 = no auth (unauthorized path)
    //            2 = expired token + refresh available
    //           -1 = error (resp already set with 401/403)
    int check_auth(const HttpRequest& req, HttpResponse& resp,
                   Authorization& auth, AuthType& auth_type,
                   std::string& refresh_token, bool& is_service);

    // ── The virtual step: execute the request ───────────────────────────────
    //
    // Called from every branch of do_fetch once authorisation is settled — on
    // the refresh branch from inside the daemon.refresh_token callback, with
    // @p req a copy that outlives the handler (connection_ctx preserved). On
    // every other branch @p req is HttpConnection::on_readable's local and dies
    // when the handler returns: copy what an async step needs before taking
    // it. The response is deferred by then: the implementation answers through
    // @p conn, and must put apply_refresh_cookies() on whatever it sends.
    //
    // The base implementation is the daemon.*fetch call — daemon.unauthorized_fetch,
    // daemon.fetch, daemon.session_fetch or daemon.authorized_fetch by the context —
    // with the result shaped by process_result. @p shaping is opaque to an
    // override; pass it on or ignore it.
    virtual void execute(const HttpRequest& req, std::shared_ptr<HttpConnection> conn,
                         const ExecContext& ctx, std::string_view method,
                         const std::string& payload, const ResultShaping& shaping);

    // ── How a refusal is worded ─────────────────────────────────────────────
    //
    // Every refusal this class produces itself goes through reply_refused():
    // synchronously from check_auth (the handler's response) and asynchronously
    // from the token-refresh callback (a fresh response sent through the
    // connection, where a derived module could not intercept it otherwise).
    // A module answering another API shape overrides it — problem+json, say —
    // from status and message; the base keeps the v1 bodies exactly.
    struct Refusal
    {
        enum class Kind
        {
            invalid,         // the token could not be verified: signature, audience, issuer, not a token
            expired,         // the token has expired and no refresh is possible here
            refresh_failed,  // daemon.refresh_token gave nothing usable
            database,        // the database refused and its payload (body) says why
            internal,        // this side broke: a failed statement, an unparsable answer
        };
        Kind             kind;
        HttpStatus       status;
        std::string_view error;    // OAuth error code when the refusal is a bearer one
                                   // ("invalid_token") — the base adds the challenge; empty otherwise
        std::string_view message;  // the reason in words
        std::string_view body;     // the database's own answer, verbatim, when the refusal
                                   // is its (an ERR-… payload); empty otherwise
        std::string_view path;     // the request's path — RFC 9457 "instance" for an override
    };

    virtual void reply_refused(HttpResponse& resp, const Refusal& refusal);

    /// Set-Cookie for the tokens of a refresh (no-op unless ctx.refreshed):
    /// access and refresh token under the user or service names, and the
    /// session id for a user context. Static on purpose: a result callback
    /// calls it after the module may be gone, and it needs nothing from it.
    static void apply_refresh_cookies(HttpResponse& resp, const ExecContext& ctx);

    Logger&                   log_;
    const OAuthProviders&     providers_;

private:
    // ── HTTP method handlers ────────────────────────────────────────────────

    void do_get(const HttpRequest& req, HttpResponse& resp);
    void do_post(const HttpRequest& req, HttpResponse& resp);
    void do_put(const HttpRequest& req, HttpResponse& resp);
    void do_patch(const HttpRequest& req, HttpResponse& resp);
    void do_delete(const HttpRequest& req, HttpResponse& resp);

    // ── Token refresh → execute() ───────────────────────────────────────────

    void token_refresh_and_fetch(const HttpRequest& req, HttpResponse& resp,
                                 const Authorization& auth,
                                 const std::string& refresh_token,
                                 std::string_view method,
                                 const std::string& payload,
                                 bool is_service,
                                 const ResultShaping& shaping);

    // ── Payload building ────────────────────────────────────────────────────

    static std::string build_payload(const HttpRequest& req);

    // ── State ───────────────────────────────────────────────────────────────

    PgPool&                   pool_;
    std::vector<std::string>  endpoints_;
    bool                      enabled_;
    PayloadTransformer        payload_transformer_;
};

} // namespace apostol

#endif // defined(WITH_POSTGRESQL) && defined(WITH_SSL)
