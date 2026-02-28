#pragma once

#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "apostol/http.hpp"
#include "apostol/apostol_module.hpp"
#include "apostol/jwt.hpp"
#include "apostol/oauth_providers.hpp"
#include "apostol/pg.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace apostol
{

class Application;

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
                   std::string& refresh_token);

    // ── Fetch variants → build SQL → exec_sql() ────────────────────────────

    void unauthorized_fetch(const HttpRequest& req, HttpResponse& resp,
                            std::string_view method,
                            const std::string& payload);

    void authorized_fetch(const HttpRequest& req, HttpResponse& resp,
                          const Authorization& auth, AuthType auth_type,
                          std::string_view method,
                          const std::string& payload);

    void token_refresh_and_fetch(const HttpRequest& req, HttpResponse& resp,
                                 const Authorization& auth,
                                 const std::string& refresh_token,
                                 std::string_view method,
                                 const std::string& payload);

    // ── Payload building ────────────────────────────────────────────────────

    static std::string build_payload(const HttpRequest& req);

    // ── State ───────────────────────────────────────────────────────────────

    PgPool&                   pool_;
    EventLoop&                loop_;
    const OAuthProviders&     providers_;
    std::vector<std::string>  endpoints_;
    bool                      enabled_;
};

} // namespace apostol

#endif // defined(WITH_POSTGRESQL) && defined(WITH_SSL)
