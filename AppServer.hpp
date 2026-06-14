#pragma once

#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "apostol/http.hpp"
#include "apostol/apostol_module.hpp"
#include "apostol/jwt.hpp"
#include "apostol/oauth_providers.hpp"
#include "apostol/pg.hpp"

#include <functional>
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
class AppServer final : public ApostolModule
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

private:
    // ── HTTP method handlers ────────────────────────────────────────────────

    void do_get(const HttpRequest& req, HttpResponse& resp);
    void do_post(const HttpRequest& req, HttpResponse& resp);
    void do_put(const HttpRequest& req, HttpResponse& resp);
    void do_patch(const HttpRequest& req, HttpResponse& resp);
    void do_delete(const HttpRequest& req, HttpResponse& resp);

    // ── Auth type ───────────────────────────────────────────────────────────

    enum class AuthType { none, bearer, session, basic_auth };

    // ── Main dispatch ───────────────────────────────────────────────────────

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

    // ── Fetch variants → build SQL → exec_sql() ────────────────────────────

    void unauthorized_fetch(const HttpRequest& req, HttpResponse& resp,
                            std::string_view method,
                            const std::string& payload,
                            const ResultShaping& shaping);

    void authorized_fetch(const HttpRequest& req, HttpResponse& resp,
                          const Authorization& auth, AuthType auth_type,
                          std::string_view method,
                          const std::string& payload,
                          const ResultShaping& shaping);

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
    const OAuthProviders&     providers_;
    std::vector<std::string>  endpoints_;
    bool                      enabled_;
    PayloadTransformer        payload_transformer_;
};

} // namespace apostol

#endif // defined(WITH_POSTGRESQL) && defined(WITH_SSL)
