/*++

Program name:

  Apostol CRM

Module Name:

  AppServer.cpp

Notices:

  Module: Application Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

//----------------------------------------------------------------------------------------------------------------------

#include "Core.hpp"
#include "AppServer.hpp"
//----------------------------------------------------------------------------------------------------------------------

#include "jwt.h"
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Module {

        //--------------------------------------------------------------------------------------------------------------

        //-- CAppServer ------------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CAppServer::CAppServer(CModuleProcess *AProcess) : CApostolModule(AProcess, "application server", "module/AppServer") {
            m_Headers.Add("Authorization");
            m_Headers.Add("Session");
            m_Headers.Add("Secret");
            m_Headers.Add("Nonce");
            m_Headers.Add("Signature");

            m_FixedDate = Now();

            CAppServer::InitMethods();

            UpdateCacheList();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::InitMethods() {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            m_Methods.AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoGet(Connection); }));
            m_Methods.AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoPost(Connection); }));
            m_Methods.AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoOptions(Connection); }));
            m_Methods.AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
#else
            m_Methods.AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , std::bind(&CAppServer::DoGet, this, _1)));
            m_Methods.AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , std::bind(&CAppServer::DoPost, this, _1)));
            m_Methods.AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , std::bind(&CAppServer::DoOptions, this, _1)));
            m_Methods.AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        CHTTPReply::CStatusType CAppServer::ErrorCodeToStatus(int ErrorCode) {
            CHTTPReply::CStatusType status = CHTTPReply::ok;

            if (ErrorCode != 0) {
                switch (ErrorCode) {
                    case 401:
                        status = CHTTPReply::unauthorized;
                        break;

                    case 403:
                        status = CHTTPReply::forbidden;
                        break;

                    case 404:
                        status = CHTTPReply::not_found;
                        break;

                    case 500:
                        status = CHTTPReply::internal_server_error;
                        break;

                    default:
                        status = CHTTPReply::bad_request;
                        break;
                }
            }

            return status;
        }
        //--------------------------------------------------------------------------------------------------------------

        int CAppServer::CheckError(const CJSON &Json, CString &ErrorMessage) {
            int errorCode = 0;

            if (Json.HasOwnProperty(_T("error"))) {
                const auto& error = Json[_T("error")];

                if (error.HasOwnProperty(_T("code"))) {
                    errorCode = error[_T("code")].AsInteger();
                } else {
                    return 0;
                }

                if (error.HasOwnProperty(_T("message"))) {
                    ErrorMessage = error[_T("message")].AsString();
                } else {
                    return 0;
                }

                if (errorCode >= 10000)
                    errorCode = errorCode / 100;

                if (errorCode < 0)
                    errorCode = 400;
            }

            return errorCode;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::DoPostgresQueryExecuted(CPQPollQuery *APollQuery) {

            auto pResult = APollQuery->Results(0);

            if (pResult->ExecStatus() != PGRES_TUPLES_OK) {
                QueryException(APollQuery, Delphi::Exception::EDBError("DBError: %s", pResult->GetErrorMessage()));
                return;
            }

            CString errorMessage;

            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->Binding());

            if (pConnection != nullptr && !pConnection->ClosedGracefully()) {

                const auto &caRequest = pConnection->Request();
                auto &Reply = pConnection->Reply();

                CStringList ResultObject;
                CStringList ResultFormat;

                ResultObject.Add("true");
                ResultObject.Add("false");

                ResultFormat.Add("object");
                ResultFormat.Add("array");
                ResultFormat.Add("null");

                const auto &result_object = caRequest.Params[_T("result_object")];
                const auto &result_format = caRequest.Params[_T("result_format")];

                if (!result_object.IsEmpty() && ResultObject.IndexOfName(result_object) == -1) {
                    ReplyError(pConnection, CHTTPReply::bad_request, CString().Format("Invalid result_object: %s", result_object.c_str()));
                    return;
                }

                if (!result_format.IsEmpty() && ResultFormat.IndexOfName(result_format) == -1) {
                    ReplyError(pConnection, CHTTPReply::bad_request, CString().Format("Invalid result_format: %s", result_format.c_str()));
                    return;
                }

                const auto &patch = pConnection->Data()["path"].Lower();
                const auto bDataArray = patch.Find(_T("/list")) != CString::npos;

                CString Format(result_format);
                if (Format.IsEmpty() && bDataArray)
                    Format = "array";

                CHTTPReply::CStatusType status = CHTTPReply::ok;

                try {
                    if (pResult->nTuples() == 1) {
                        const CJSON Payload(pResult->GetValue(0, 0));
                        status = ErrorCodeToStatus(CheckError(Payload, errorMessage));
                    }

                    PQResultToJson(pResult, Reply.Content, Format, result_object == "true" ? "result" : CString());

                    if (status == CHTTPReply::ok && !Reply.CacheFile.IsEmpty()) {
                        Reply.Content.SaveToFile(Reply.CacheFile.c_str());
                    }
                } catch (Delphi::Exception::Exception &E) {
                    errorMessage = E.what();
                    status = CHTTPReply::bad_request;
                    Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
                }

                if (status == CHTTPReply::ok) {
                    pConnection->SendReply(status, nullptr, true);
                } else {
                    ReplyError(pConnection, status, errorMessage);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->Binding());
            ReplyError(pConnection, CHTTPReply::internal_server_error, E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            QueryException(APollQuery, E);
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CAppServer::GetSession(const CHTTPRequest &Request) {
            const auto& headerSession = Request.Headers.Values(_T("Session"));
            const auto& cookieSession = Request.Cookies.Values(_T("SID"));

            return headerSession.IsEmpty() ? cookieSession : headerSession;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::CheckSession(const CHTTPRequest &Request, CString &Session) {
            const auto& caSession = GetSession(Request);

            if (caSession.Length() != 40)
                return false;

            Session = caSession;

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::CacheAge(const CString &FileName) {
            if (FileName.IsEmpty() || !FileExists(FileName.c_str()))
                return false;

            time_t age = FileAge(FileName.c_str());
            if (age == -1)
                return false;

            time_t now = time(nullptr);

            return (now - age) <= 1 * 60; // 1 min
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CAppServer::GetCacheFile(const CString &Session, const CString &Path, const CString &Payload) {
            CString sCacheFile;
            CString sData;

            int Index = m_CacheList.IndexOf(Path);

            if (Index != -1) {

                sCacheFile = Config()->CachePrefix();
                sCacheFile += Session;
                sCacheFile += Path;
                sCacheFile += _T("/");

                if (!DirectoryExists(sCacheFile.c_str())) {
                    if (!ForceDirectories(sCacheFile.c_str())) {
                        throw EOSError(errno, "force directories (%s) failed", sCacheFile.c_str());
                    }
                }

                sData = Path;
                sData += Payload.IsEmpty() ? "null" : Payload;

                sCacheFile += SHA1(sData);
            }

            return sCacheFile;
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CAppServer::VerifyToken(const CString &Token) {

            const auto& GetSecret = [](const CProvider &Provider, const CString &Application) {
                const auto &Secret = Provider.Secret(Application);
                if (Secret.IsEmpty())
                    throw ExceptionFrm("Not found Secret for \"%s:%s\"", Provider.Name().c_str(), Application.c_str());
                return Secret;
            };

            auto decoded = jwt::decode(Token);
            const auto& aud = CString(decoded.get_audience());

            CString Application;

            const auto& Providers = Server().Providers();

            const auto Index = OAuth2::Helper::ProviderByClientId(Providers, aud, Application);
            if (Index == -1)
                throw COAuth2Error(_T("Not found provider by Client ID."));

            const auto& Provider = Providers[Index].Value();

            const auto& iss = CString(decoded.get_issuer());

            CStringList Issuers;
            Provider.GetIssuers(Application, Issuers);
            if (Issuers[iss].IsEmpty())
                throw jwt::error::token_verification_exception(jwt::error::token_verification_error::issuer_missmatch);

            const auto& alg = decoded.get_algorithm();
            const auto& ch = alg.substr(0, 2);

            const auto& Secret = GetSecret(Provider, Application);

            if (ch == "HS") {
                if (alg == "HS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs256{Secret});
                    verifier.verify(decoded);

                    return Token; // if algorithm HS256
                } else if (alg == "HS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs384{Secret});
                    verifier.verify(decoded);
                } else if (alg == "HS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs512{Secret});
                    verifier.verify(decoded);
                }
            } else if (ch == "RS") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "RS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs256{key});
                    verifier.verify(decoded);
                } else if (alg == "RS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs384{key});
                    verifier.verify(decoded);
                } else if (alg == "RS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs512{key});
                    verifier.verify(decoded);
                }
            } else if (ch == "ES") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "ES256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es256{key});
                    verifier.verify(decoded);
                } else if (alg == "ES384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es384{key});
                    verifier.verify(decoded);
                } else if (alg == "ES512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es512{key});
                    verifier.verify(decoded);
                }
            } else if (ch == "PS") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "PS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps256{key});
                    verifier.verify(decoded);
                } else if (alg == "PS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps384{key});
                    verifier.verify(decoded);
                } else if (alg == "PS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps512{key});
                    verifier.verify(decoded);
                }
            }

            const auto& Result = CCleanToken(R"({"alg":"HS256","typ":"JWT"})", decoded.get_payload(), true);

            std::error_code ec;
            return Result.Sign(jwt::algorithm::hs256{Secret}, ec);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::SetSecure(CHTTPReply &Reply, const CString &AccessToken, const CString &RefreshToken, const CString &Session, const CString &Domain) {
            if (!AccessToken.IsEmpty())
                Reply.SetCookie(_T("__Secure-AT"), AccessToken.c_str(), _T("/"), 60 * SecsPerDay, true, _T("None"), true, Domain.c_str());

            if (!RefreshToken.IsEmpty())
                Reply.SetCookie(_T("__Secure-RT"), RefreshToken.c_str(), _T("/"), 60 * SecsPerDay, true, _T("None"), true, Domain.c_str());

            if (!Session.IsEmpty())
                Reply.SetCookie(_T("SID"), Session.c_str(), _T("/"), 60 * SecsPerDay);
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::FindToken(const CHTTPRequest &Request, CAuthorization &Authorization) {
            const auto &access_token = Request.Cookies.Values(_T("__Secure-AT"));
            const auto &refresh_token = Request.Cookies.Values(_T("__Secure-RT"));

            if (access_token.empty())
                return false;

            Authorization.Schema = CAuthorization::asBearer;
            Authorization.Type = CAuthorization::atSession;
            Authorization.Token = access_token;

            if (!refresh_token.empty())
                Authorization.Password = CHTTPServer::URLDecode(refresh_token);

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::FindSession(const CHTTPRequest &Request, CAuthorization &Authorization) {
            const auto &caHeaders = Request.Headers;

            const auto &headerSession = caHeaders.Values(_T("Session"));
            const auto &headerSecret = caHeaders.Values(_T("Secret"));

            Authorization.Username = headerSession;
            Authorization.Password = headerSecret;

            if (Authorization.Username.IsEmpty() || Authorization.Password.IsEmpty())
                return false;

            Authorization.Schema = CAuthorization::asBasic;
            Authorization.Type = CAuthorization::atSession;

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::CheckAuthorizationData(const CHTTPRequest &Request, CAuthorization &Authorization) {
            const auto &caHeaders = Request.Headers;
            const auto &caAuthorization = caHeaders.Values(_T("Authorization"));

            if (caAuthorization.IsEmpty()) {
                if (FindSession(Request, Authorization))
                    return true;

                if (FindToken(Request, Authorization))
                    return true;
            } else {
                Authorization << caAuthorization;
                return true;
            }

            return false;
        }
        //--------------------------------------------------------------------------------------------------------------

        int CAppServer::CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization) {

            const auto &caRequest = AConnection->Request();

            try {
                if (CheckAuthorizationData(caRequest, Authorization)) {
                    if (Authorization.Schema == CAuthorization::asBearer) {
                        AConnection->Data().Values("Authorization", "Bearer " + Authorization.Token);
                        Authorization.Token = VerifyToken(Authorization.Token);
                    }

                    return 1;
                }
#ifdef CALL_UNAUTHORIZED_FETCH
                return 0;
#else
                if (Authorization.Schema == CAuthorization::asBasic)
                    AConnection->Data().Values("Authorization", "Basic");

                ReplyError(AConnection, CHTTPReply::unauthorized, "Unauthorized.");
#endif
            } catch (jwt::error::token_expired_exception &e) {
                if (Authorization.Schema == CAuthorization::asBearer && Authorization.Type == CAuthorization::atSession && !Authorization.Password.IsEmpty())
                    return 2;
                ReplyError(AConnection, CHTTPReply::forbidden, e.what());
            } catch (jwt::error::token_verification_exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            } catch (CAuthorizationError &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            } catch (COAuth2Error &e) {
                return 2;
            } catch (std::exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            }

            return -1;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::CheckTokenAuthorization(CHTTPServerConnection *AConnection, const CString& Action,
                const CAuthorization &Authorization, COnSocketExecuteEvent &&OnContinue) {

            auto OnExecuted = [OnContinue](CPQPollQuery *APollQuery) {
                auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->Binding());

                if (pConnection == nullptr)
                    return;

                try {
                    auto pResult = APollQuery->Results(0);

                    if (pResult->ExecStatus() != PGRES_TUPLES_OK) {
                        throw Delphi::Exception::EDBError(pResult->GetErrorMessage());
                    }

                    pConnection->Data().Values("payload", pResult->GetValue(0, 0));

                    OnContinue(pConnection);
                } catch (Delphi::Exception::Exception &E) {
                    ReplyError(pConnection, CHTTPReply::bad_request, E.what());
                }
            };

            auto OnException = [](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->Binding());
                ReplyError(pConnection, CHTTPReply::bad_request, E.what());
            };

            const auto &caRequest = AConnection->Request();

            try {
                if (Authorization.Schema == CAuthorization::asBearer) {
                    CStringList SQL;

                    AConnection->Data().Values("action", Action);

                    if (Action == "refresh_token") {
                        SQL.Add(CString().Format("SELECT daemon.%s(%s, %s);", Action.c_str(), PQQuoteLiteral(Authorization.Token).c_str(), PQQuoteLiteral(Authorization.Password).c_str()));
                    } else {
                        SQL.Add(CString().Format("SELECT daemon.%s(%s);", Action.c_str(), PQQuoteLiteral(Authorization.Token).c_str()));
                    }

                    ExecSQL(SQL, AConnection, OnExecuted, OnException);

                } else {

                    if (Authorization.Schema == CAuthorization::asBasic)
                        AConnection->Data().Values("Authorization", "Basic");

                    ReplyError(AConnection, CHTTPReply::unauthorized, "Unauthorized.");
                }
            } catch (std::exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::LoadCerts() {
            const CString pathCerts = Config()->Prefix() + _T("certs/");
            const CString lockFile = pathCerts + "lock";
            if (!FileExists(lockFile.c_str())) {
                auto& Providers = Server().Providers();
                for (int i = 0; i < Providers.Count(); i++) {
                    auto &Provider = Providers[i].Value();
                    if (FileExists(CString(pathCerts + Provider.Name()).c_str())) {
                        Provider.Keys().Clear();
                        Provider.Keys().LoadFromFile(CString(pathCerts + Provider.Name()).c_str());
                    }
                }
            } else {
                m_FixedDate = Now() + (CDateTime) 1 / SecsPerDay; // 1 sec
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::UpdateCacheList() {
            CString sFile;
            sFile = Config()->Prefix() + _T("cache.conf");
            if (FileExists(sFile.c_str())) {
                m_CacheList.LoadFromFile(sFile.c_str());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, const CString &Agent, const CString &Host) {

            CStringList SQL;

            const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

            SQL.Add(CString()
                .MaxFormatSize(256 + Method.Size() + Path.Size() + caPayload.Size() + Agent.Size())
                .Format("SELECT * FROM daemon.unauthorized_fetch(%s, %s, %s::jsonb, %s, %s);",
                                     PQQuoteLiteral(Method).c_str(),
                                     PQQuoteLiteral(Path).c_str(),
                                     caPayload.c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str()
            ));

            AConnection->Data().Values("method", Method);
            AConnection->Data().Values("path", Path);
            AConnection->Data().Values("authorized", "false");
            AConnection->Data().Values("signature", "false");

            try {
                ExecSQL(SQL, AConnection);
            } catch (Delphi::Exception::Exception &E) {
                AConnection->SendStockReply(CHTTPReply::service_unavailable);
                Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization,
                const CString &Method, const CString &Path, const CString &Payload, const CString &Agent, const CString &Host) {

            CStringList SQL;

            if (Authorization.Schema == CAuthorization::asBearer) {

                const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

                SQL.Add(CString()
                    .MaxFormatSize(256 + Authorization.Token.Size() + Method.Size() + Path.Size() + caPayload.Size() + Agent.Size())
                    .Format("SELECT * FROM daemon.fetch(%s, %s, %s, %s::jsonb, %s, %s);",
                                         PQQuoteLiteral(Authorization.Token).c_str(),
                                         PQQuoteLiteral(Method).c_str(),
                                         PQQuoteLiteral(Path).c_str(),
                                         caPayload.c_str(),
                                         PQQuoteLiteral(Agent).c_str(),
                                         PQQuoteLiteral(Host).c_str()
                ));

            } else if (Authorization.Schema == CAuthorization::asBasic) {

                const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

                SQL.Add(CString()
                    .MaxFormatSize(256 + Method.Size() + Path.Size() + caPayload.Size() + Agent.Size())
                    .Format("SELECT * FROM daemon.%s_fetch(%s, %s, %s, %s, %s::jsonb, %s, %s);",
                                         Authorization.Type == CAuthorization::atSession ? "session" : "authorized",
                                         PQQuoteLiteral(Authorization.Username).c_str(),
                                         PQQuoteLiteral(Authorization.Password).c_str(),
                                         PQQuoteLiteral(Method).c_str(),
                                         PQQuoteLiteral(Path).c_str(),
                                         caPayload.c_str(),
                                         PQQuoteLiteral(Agent).c_str(),
                                         PQQuoteLiteral(Host).c_str()
                ));

            } else {

                return UnauthorizedFetch(AConnection, Method, Path, Payload, Agent, Host);

            }

            AConnection->Data().Values("method", Method);
            AConnection->Data().Values("path", Path);
            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "false");

            try {
                ExecSQL(SQL, AConnection);
            } catch (Delphi::Exception::Exception &E) {
                AConnection->SendStockReply(CHTTPReply::service_unavailable);
                Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::SignedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, const CString &Session, const CString &Nonce, const CString &Signature,
                const CString &Agent, const CString &Host, long int ReceiveWindow) {

            CStringList SQL;

            const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

            SQL.Add(CString()
                .MaxFormatSize(256 + Method.Size() + Path.Size() + caPayload.Size() + Session.Size() + Nonce.Size() + Signature.Size() + Agent.Size())
                .Format("SELECT * FROM daemon.signed_fetch(%s, %s, %s::json, %s, %s, %s, %s, %s, INTERVAL '%d milliseconds');",
                                     PQQuoteLiteral(Method).c_str(),
                                     PQQuoteLiteral(Path).c_str(),
                                     caPayload.c_str(),
                                     PQQuoteLiteral(Session).c_str(),
                                     PQQuoteLiteral(Nonce).c_str(),
                                     PQQuoteLiteral(Signature).c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str(),
                                     ReceiveWindow
            ));

            AConnection->Data().Values("method", Method);
            AConnection->Data().Values("path", Path);
            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "true");

            try {
                ExecSQL(SQL, AConnection);
            } catch (Delphi::Exception::Exception &E) {
                AConnection->SendStockReply(CHTTPReply::service_unavailable);
                Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::DoFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path) {

            auto OnContinue = [this](CTCPConnection *AConnection) {

                auto pConnection = dynamic_cast<CHTTPServerConnection *> (AConnection);

                if (pConnection != nullptr && pConnection->Connected()) {
                    const auto &Request = pConnection->Request();
                    auto &Reply = pConnection->Reply();

                    const CJSON Payload(pConnection->Data()["payload"]);

                    CString ErrorMessage;

                    const auto status = ErrorCodeToStatus(CheckError(Payload, ErrorMessage));

                    if (status == CHTTPReply::ok) {
                        CAuthorization Authorization;

                        const auto &caAction = pConnection->Data().Values(_T("action"));

                        if (caAction == "refresh_token") {
                            const auto &access_token = Payload[_T("access_token")].AsString();
                            const auto &refresh_token = Payload[_T("refresh_token")].AsString();
                            const auto &session = Payload[_T("session")].AsString();

                            SetSecure(Reply, access_token, refresh_token, session, Request.Location.hostname);

                            Authorization.Schema = CAuthorization::asBearer;
                            Authorization.Token = access_token;
                        } else {
                            Authorization << pConnection->Data().Values(_T("Authorization"));
                        }

                        const auto &caContentType = Request.Headers.Values(_T("Content-Type")).Lower();
                        const auto &caPath = Request.Location.pathname;

                        const auto bContentJson = (caContentType.Find(_T("application/json")) != CString::npos);

                        CJSON Json;
                        if (!bContentJson) {
                            ContentToJson(Request, Json);
                        }

                        const auto &caPayload = bContentJson ? Request.Content : Json.ToString();

                        const auto &caAgent = GetUserAgent(pConnection);
                        const auto &caHost = GetRealIP(pConnection);

                        AuthorizedFetch(pConnection, Authorization, "POST", caPath, caPayload, caAgent, caHost);
                    } else {
                        ReplyError(pConnection, status, ErrorMessage);
                    }

                    return true;
                }

                return false;
            };

            const auto &caRequest = AConnection->Request();

            const auto &caContentType = caRequest.Headers.Values(_T("Content-Type")).Lower();
            const auto bContentJson = (caContentType.Find(_T("application/json")) != CString::npos);

            CJSON Json;
            if (!bContentJson) {
                ContentToJson(caRequest, Json);
            }

            const auto &caPayload = bContentJson ? caRequest.Content : Json.ToString();
            const auto &caSignature = caRequest.Headers.Values(_T("Signature"));

            const auto &caAgent = GetUserAgent(AConnection);
            const auto &caHost = GetRealIP(AConnection);

            try {
                if (caSignature.IsEmpty()) {
                    CAuthorization Authorization;
                    const auto checkAuthorization = CheckAuthorization(AConnection, Authorization);
#ifdef CALL_UNAUTHORIZED_FETCH
                    if (checkAuthorization == 0) {
                        UnauthorizedFetch(AConnection, Method, Path, caPayload, caAgent, caHost);
                    } else if (checkAuthorization == 1) {
#else
                    if (checkAuthorization == 1) {
#endif
                        AuthorizedFetch(AConnection, Authorization, Method, Path, caPayload, caAgent, caHost);
                    } else if (checkAuthorization == 2) {
                        CheckTokenAuthorization(AConnection, Authorization.Type == CAuthorization::atSession ? "refresh_token" : "validation", Authorization, OnContinue);
                    }
                } else {
                    const auto& caSession = GetSession(caRequest);
                    const auto& caNonce = caRequest.Headers.Values(_T("Nonce"));

                    long int receiveWindow = 5000;
                    const auto& caReceiveWindow = caRequest.Params[_T("receive_window")];
                    if (!caReceiveWindow.IsEmpty())
                        receiveWindow = StrToIntDef(caReceiveWindow.c_str(), receiveWindow);

                    SignedFetch(AConnection, Method, Path, caPayload, caSession, caNonce, caSignature, caAgent, caHost, receiveWindow);
                }
            } catch (std::exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::DoGet(CHTTPServerConnection *AConnection) {

            const auto &caRequest = AConnection->Request();
            auto &Reply = AConnection->Reply();

            Reply.ContentType = CHTTPReply::json;

            const auto &path = caRequest.Location.pathname;

            if (path.IsEmpty()) {
                AConnection->SendStockReply(CHTTPReply::not_found);
                return;
            }

            try {
                if (path == "/api/v1/ping") {

                    AConnection->SendStockReply(CHTTPReply::ok);

                } else if (path == "/api/v1/time") {

                    Reply.Content << "{\"serverTime\": " << CString::ToString(MsEpoch()) << "}";

                    AConnection->SendReply(CHTTPReply::ok);

                } else {

                    DoFetch(AConnection, "GET", path);

                }
            } catch (Delphi::Exception::Exception &E) {
                AConnection->CloseConnection(true);
                ReplyError(AConnection, CHTTPReply::bad_request, E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::DoPost(CHTTPServerConnection *AConnection) {

            const auto &caRequest = AConnection->Request();
            auto &Reply = AConnection->Reply();

            Reply.ContentType = CHTTPReply::json;

            const auto &path = caRequest.Location.pathname;

            if (path.IsEmpty()) {
                AConnection->SendStockReply(CHTTPReply::not_found);
                return;
            }

            DoFetch(AConnection, "POST", path);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::Heartbeat(CDateTime DateTime) {
            if ((DateTime >= m_FixedDate)) {
                m_FixedDate = DateTime + (CDateTime) 30 / MinsPerDay; // 30 min
                LoadCerts();
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool(SectionName(), "enable", true) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::CheckLocation(const CLocation &Location) {
            return Location.pathname.SubString(0, 5) == _T("/api/");
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}
}