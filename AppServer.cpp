/*++

Program name:

  Apostol Web Service

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

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CAppServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CAppServer::CAppServer(CModuleProcess *AProcess) : CApostolModule(AProcess, "application server") {
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
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoGet(Connection); }));
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoPost(Connection); }));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoOptions(Connection); }));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
#else
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(true, std::bind(&CAppServer::DoGet, this, _1)));
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(true, std::bind(&CAppServer::DoPost, this, _1)));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true, std::bind(&CAppServer::DoOptions, this, _1)));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, std::bind(&CAppServer::MethodNotAllowed, this, _1)));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        CReply::CStatusType CAppServer::ErrorCodeToStatus(int ErrorCode) {
            CReply::CStatusType Status = CReply::ok;

            if (ErrorCode != 0) {
                switch (ErrorCode) {
                    case 401:
                        Status = CReply::unauthorized;
                        break;

                    case 403:
                        Status = CReply::forbidden;
                        break;

                    case 404:
                        Status = CReply::not_found;
                        break;

                    case 500:
                        Status = CReply::internal_server_error;
                        break;

                    default:
                        Status = CReply::bad_request;
                        break;
                }
            }

            return Status;
        }
        //--------------------------------------------------------------------------------------------------------------

        int CAppServer::CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError) {
            int ErrorCode = 0;

            if (Json.HasOwnProperty(_T("error"))) {
                const auto& error = Json[_T("error")];

                if (error.HasOwnProperty(_T("code"))) {
                    ErrorCode = error[_T("code")].AsInteger();
                } else {
                    ErrorCode = 40000;
                }

                if (error.HasOwnProperty(_T("message"))) {
                    ErrorMessage = error[_T("message")].AsString();
                } else {
                    ErrorMessage = _T("Invalid request.");
                }

                if (RaiseIfError)
                    throw EDBError(ErrorMessage.c_str());

                if (ErrorCode >= 10000)
                    ErrorCode = ErrorCode / 100;
            }

            return ErrorCode;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload) {

            if (Path == _T("/sign/out")) {

                auto LReply = AConnection->Reply();

                LReply->SetCookie(_T("SID"), _T("null"), _T("/"), -1);

            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::DoPostgresQueryExecuted(CPQPollQuery *APollQuery) {
            clock_t start = clock();

            auto LResult = APollQuery->Results(0);

            if (LResult->ExecStatus() != PGRES_TUPLES_OK) {
                QueryException(APollQuery, Delphi::Exception::EDBError(LResult->GetErrorMessage()));
                return;
            }

            CString ErrorMessage;

            auto LConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

            if (LConnection != nullptr) {

                const auto& Path = LConnection->Data()["path"].Lower();
                const auto DataArray = Path.Find(_T("/list")) != CString::npos;

                auto LRequest = LConnection->Request();
                auto LReply = LConnection->Reply();

                const auto& result_object = LRequest->Params[_T("result_object")];
                const auto& data_array = LRequest->Params[_T("data_array")];

                CReply::CStatusType LStatus = CReply::ok;

                try {
                    if (LResult->nTuples() == 1) {
                        const CJSON Payload(LResult->GetValue(0, 0));
                        LStatus = ErrorCodeToStatus(CheckError(Payload, ErrorMessage));
                        if (LStatus == CReply::ok) {
                            AfterQuery(LConnection, Path, Payload);
                        }
                    }

                    PQResultToJson(LResult, LReply->Content, data_array.IsEmpty() ? DataArray : data_array == "true", result_object == "true" ? "result" : CString());

                    if (LStatus == CReply::ok && !LReply->CacheFile.IsEmpty()) {
                        LReply->Content.SaveToFile(LReply->CacheFile.c_str());
                    }
                } catch (Delphi::Exception::Exception &E) {
                    ErrorMessage = E.what();
                    LStatus = CReply::bad_request;
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }

                if (LStatus == CReply::ok) {
                    LConnection->SendReply(LStatus, nullptr, true);
                } else {
                    ReplyError(LConnection, LStatus, ErrorMessage);
                }

            } else {

                auto LJob = m_pJobs->FindJobByQuery(APollQuery);
                if (LJob == nullptr) {
                    Log()->Error(APP_LOG_EMERG, 0, _T("Job not found by Query."));
                    return;
                }

                const auto& Path = LJob->Data()["path"].Lower();
                const auto DataArray = Path.Find(_T("/list")) != CString::npos;

                auto LReply = &LJob->Reply();
                LReply->Status = CReply::ok;

                try {
                    if (LResult->nTuples() == 1) {
                        const CJSON Payload(LResult->GetValue(0, 0));
                        LReply->Status = ErrorCodeToStatus(CheckError(Payload, ErrorMessage));
                    }

                    PQResultToJson(LResult, LReply->Content, DataArray);
                } catch (Delphi::Exception::Exception &E) {
                    LReply->Status = CReply::bad_request;
                    ExceptionToJson(LReply->Status, E, LReply->Content);
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }
            }

            log_debug1(APP_LOG_DEBUG_CORE, Log(), 0, _T("Query executed runtime: %.2f ms."), (double) ((clock() - start) / (double) CLOCKS_PER_SEC * 1000));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {

            auto LConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

            if (LConnection == nullptr) {
                auto LJob = m_pJobs->FindJobByQuery(APollQuery);
                if (LJob != nullptr) {
                    ExceptionToJson(CReply::internal_server_error, E, LJob->Reply().Content);
                }
            } else {
                auto LReply = LConnection->Reply();

                ExceptionToJson(CReply::internal_server_error, E, LReply->Content);
                LConnection->SendReply(CReply::ok, nullptr, true);
            }

            Log()->Error(APP_LOG_EMERG, 0, E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            QueryException(APollQuery, E);
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CAppServer::GetSession(CRequest *ARequest) {

            const auto& headerSession = ARequest->Headers.Values(_T("Session"));
            const auto& cookieSession = ARequest->Cookies.Values(_T("SID"));

            return headerSession.IsEmpty() ? cookieSession : headerSession;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::CheckSession(CRequest *ARequest, CString &Session) {

            const auto& LSession = GetSession(ARequest);

            if (LSession.Length() != 40)
                return false;

            Session = LSession;

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
            CString LCacheFile;
            CString LData;

            int Index = m_CacheList.IndexOf(Path);

            if (Index != -1) {

                LCacheFile = Config()->CachePrefix();
                LCacheFile += Session;
                LCacheFile += Path;
                LCacheFile += _T("/");

                if (!DirectoryExists(LCacheFile.c_str())) {
                    if (!ForceDirectories(LCacheFile.c_str())) {
                        throw EOSError(errno, "force directories (%s) failed", LCacheFile.c_str());
                    }
                }

                LData = Path;
                LData += Payload.IsEmpty() ? "null" : Payload;

                LCacheFile += SHA1(LData);
            }

            return LCacheFile;
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CAppServer::VerifyToken(const CString &Token) {

            const auto& GetSecret = [](const CProvider &Provider, const CString &Application) {
                const auto &Secret = Provider.Secret(Application);
                if (Secret.IsEmpty())
                    throw ExceptionFrm("Not found Secret for \"%s:%s\"",
                                       Provider.Name.c_str(),
                                       Application.c_str()
                    );
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
            const CStringList& Issuers = Provider.GetIssuers(Application);
            if (Issuers[iss].IsEmpty())
                throw jwt::token_verification_exception("Token doesn't contain the required issuer.");

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

            return Result.Sign(jwt::algorithm::hs256{Secret});
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::CheckAuthorizationData(CRequest *ARequest, CAuthorization &Authorization) {

            const auto &LHeaders = ARequest->Headers;
            const auto &LCookies = ARequest->Cookies;

            const auto &LAuthorization = LHeaders.Values(_T("Authorization"));

            if (LAuthorization.IsEmpty()) {

                const auto &headerSession = LHeaders.Values(_T("Session"));
                const auto &headerSecret = LHeaders.Values(_T("Secret"));

                Authorization.Username = headerSession;
                Authorization.Password = headerSecret;

                if (Authorization.Username.IsEmpty() || Authorization.Password.IsEmpty())
                    return false;

                Authorization.Schema = CAuthorization::asBasic;
                Authorization.Type = CAuthorization::atSession;

            } else {
                Authorization << LAuthorization;
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization) {

            auto LRequest = AConnection->Request();

            try {
                if (CheckAuthorizationData(LRequest, Authorization)) {
                    if (Authorization.Schema == CAuthorization::asBearer) {
                        Authorization.Token = VerifyToken(Authorization.Token);
                        return true;
                    }
                }

                if (Authorization.Schema == CAuthorization::asBasic)
                    AConnection->Data().Values("Authorization", "Basic");

                ReplyError(AConnection, CReply::unauthorized, "Unauthorized.");
            } catch (jwt::token_expired_exception &e) {
                ReplyError(AConnection, CReply::forbidden, e.what());
            } catch (jwt::token_verification_exception &e) {
                ReplyError(AConnection, CReply::bad_request, e.what());
            } catch (CAuthorizationError &e) {
                ReplyError(AConnection, CReply::bad_request, e.what());
            } catch (Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CReply::bad_request, E.what());
            }

            return false;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::LoadCerts() {
            const CString pathCerts = Config()->Prefix() + _T("certs/");
            const CString lockFile = pathCerts + "lock";
            if (!FileExists(lockFile.c_str())) {
                auto& Providers = Server().Providers();
                for (int i = 0; i < Providers.Count(); i++) {
                    auto &Provider = Providers[i].Value();
                    if (FileExists(CString(pathCerts + Provider.Name).c_str())) {
                        Provider.Keys.Clear();
                        Provider.Keys.LoadFromFile(CString(pathCerts + Provider.Name).c_str());
                    }
                }
            } else {
                m_FixedDate = Now() + (CDateTime) 1 / SecsPerDay; // 1 sec
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::UpdateCacheList() {
            CString LFile;
            LFile = Config()->Prefix() + _T("cache.conf");
            if (FileExists(LFile.c_str())) {
                m_CacheList.LoadFromFile(LFile.c_str());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &Path, const CString &Payload,
                                            const CString &Agent, const CString &Host) {

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.unauthorized_fetch(%s, '%s'::jsonb, %s, %s);",
                                     PQQuoteLiteral(Path).c_str(),
                                     Payload.IsEmpty() ? "{}" : Payload.c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str()
            ));

            AConnection->Data().Values("authorized", "false");
            AConnection->Data().Values("signature", "false");
            AConnection->Data().Values("path", Path);

            if (!StartQuery(AConnection, SQL)) {
                AConnection->SendStockReply(CReply::service_unavailable);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization,
                                          const CString &Path, const CString &Payload, const CString &Agent, const CString &Host) {

            CStringList SQL;

            if (Authorization.Schema == CAuthorization::asBearer) {

                SQL.Add(CString().Format("SELECT * FROM daemon.fetch(%s, %s, '%s'::jsonb, %s, %s);",
                                         PQQuoteLiteral(Authorization.Token).c_str(),
                                         PQQuoteLiteral(Path).c_str(),
                                         Payload.IsEmpty() ? "{}" : Payload.c_str(),
                                         PQQuoteLiteral(Agent).c_str(),
                                         PQQuoteLiteral(Host).c_str()
                ));

            } else if (Authorization.Schema == CAuthorization::asBasic) {

                SQL.Add(CString().Format("SELECT * FROM daemon.%s_fetch(%s, %s, %s, '%s'::jsonb, %s, %s);",
                                         Authorization.Type == CAuthorization::atSession ? "session" : "authorized",
                                         PQQuoteLiteral(Authorization.Username).c_str(),
                                         PQQuoteLiteral(Authorization.Password).c_str(),
                                         PQQuoteLiteral(Path).c_str(),
                                         Payload.IsEmpty() ? "{}" : Payload.c_str(),
                                         PQQuoteLiteral(Agent).c_str(),
                                         PQQuoteLiteral(Host).c_str()
                ));

            } else {

                return UnauthorizedFetch(AConnection, Path, Payload, Agent, Host);

            }

            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "false");
            AConnection->Data().Values("path", Path);

            if (!StartQuery(AConnection, SQL)) {
                AConnection->SendStockReply(CReply::service_unavailable);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::SignedFetch(CHTTPServerConnection *AConnection, const CString &Path, const CString &Payload,
                                      const CString &Session, const CString &Nonce, const CString &Signature, const CString &Agent,
                                      const CString &Host, long int ReceiveWindow) {

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.signed_fetch(%s, '%s'::json, %s, %s, %s, %s, %s, INTERVAL '%d milliseconds');",
                                     PQQuoteLiteral(Path).c_str(),
                                     Payload.IsEmpty() ? "{}" : Payload.c_str(),
                                     PQQuoteLiteral(Session).c_str(),
                                     PQQuoteLiteral(Nonce).c_str(),
                                     PQQuoteLiteral(Signature).c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str(),
                                     ReceiveWindow
            ));

            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "true");
            AConnection->Data().Values("path", Path);

            if (!StartQuery(AConnection, SQL)) {
                AConnection->SendStockReply(CReply::service_unavailable);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::DoFetch(CHTTPServerConnection *AConnection, const CString &Path) {

            auto LRequest = AConnection->Request();
            auto LReply = AConnection->Reply();

            const auto& LContentType = LRequest->Headers.Values(_T("Content-Type")).Lower();
            const auto LContentJson = (LContentType.Find(_T("application/json")) != CString::npos);

            CJSON Json;
            if (!LContentJson) {
                ContentToJson(LRequest, Json);
            }

            const auto& LPayload = LContentJson ? LRequest->Content : Json.ToString();
            const auto& LSignature = LRequest->Headers.Values(_T("Signature"));

            const auto& LAgent = GetUserAgent(AConnection);
            const auto& LHost = GetHost(AConnection);

            try {
                if (LSignature.IsEmpty()) {
                    CAuthorization LAuthorization;
                    if (CheckAuthorization(AConnection, LAuthorization)) {
                        CString LSession;
                        if (CheckSession(LRequest, LSession)) {
                            LReply->CacheFile = GetCacheFile(LSession, Path, LPayload);
                            if (CacheAge(LReply->CacheFile)) {
                                LReply->Content.LoadFromFile(LReply->CacheFile);
                                AConnection->SendReply(CReply::ok);
                                return;
                            }
                        }
                        AuthorizedFetch(AConnection, LAuthorization, Path, LPayload, LAgent, LHost);
                    }
                } else {
                    const auto& LSession = GetSession(LRequest);
                    const auto& LNonce = LRequest->Headers.Values(_T("Nonce"));

                    long int LReceiveWindow = 5000;
                    const auto& receiveWindow = LRequest->Params[_T("receive_window")];
                    if (!receiveWindow.IsEmpty())
                        LReceiveWindow = StrToIntDef(receiveWindow.c_str(), LReceiveWindow);

                    SignedFetch(AConnection, Path, LPayload, LSession, LNonce, LSignature, LAgent, LHost, LReceiveWindow);
                }
            } catch (Delphi::Exception::Exception &E) {
                ExceptionToJson(CReply::bad_request, E, LReply->Content);
                AConnection->SendReply(CReply::ok);
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::ReplyError(CHTTPServerConnection *AConnection, CReply::CStatusType ErrorCode, const CString &Message) {
            auto LReply = AConnection->Reply();

            if (ErrorCode == CReply::unauthorized) {
                CReply::AddUnauthorized(LReply, AConnection->Data()["Authorization"] != "Basic", "invalid_client", Message.c_str());
            }

            LReply->Content.Clear();
            LReply->Content.Format(R"({"error": {"code": %u, "message": "%s"}})", ErrorCode, Delphi::Json::EncodeJsonString(Message).c_str());

            AConnection->SendReply(ErrorCode, nullptr, true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::DoGet(CHTTPServerConnection *AConnection) {
            auto LRequest = AConnection->Request();
            auto LReply = AConnection->Reply();

            LReply->ContentType = CReply::json;

            CStringList LRouts;
            SplitColumns(LRequest->Location.pathname, LRouts, '/');

            if (LRouts.Count() < 3) {
                AConnection->SendStockReply(CReply::not_found);
                return;
            }

            const auto& LService = LRouts[0].Lower();
            const auto& LVersion = LRouts[1].Lower();
            const auto& LCommand = LRouts[2].Lower();

            if (LVersion == "v1") {
                m_Version = 1;
            } else if (LVersion == "v2") {
                m_Version = 2;
            }

            if (LService != "api" || (m_Version == -1)) {
                AConnection->SendStockReply(CReply::not_found);
                return;
            }

            try {
                if (LCommand == "ping") {

                    AConnection->SendStockReply(CReply::ok);

                } else if (LCommand == "time") {

                    LReply->Content << "{\"serverTime\": " << LongToString(MsEpoch()) << "}";

                    AConnection->SendReply(CReply::ok);

                } else if (m_Version == 2) {

                    if (LRouts.Count() != 3) {
                        AConnection->SendStockReply(CReply::bad_request);
                        return;
                    }

                    const auto& Identity = LRouts[2];

                    if (Identity.Length() != APOSTOL_MODULE_UID_LENGTH) {
                        AConnection->SendStockReply(CReply::bad_request);
                        return;
                    }

                    auto LJob = m_pJobs->FindJobById(Identity);

                    if (LJob == nullptr) {
                        AConnection->SendStockReply(CReply::not_found);
                        return;
                    }

                    if (LJob->Reply().Content.IsEmpty()) {
                        AConnection->SendStockReply(CReply::no_content);
                        return;
                    }

                    LReply->Content = LJob->Reply().Content;

                    CReply::GetReply(LReply, CReply::ok);

                    LReply->Headers << LJob->Reply().Headers;

                    AConnection->SendReply();

                    delete LJob;

                } else {

                    CString LPath;
                    for (int I = 2; I < LRouts.Count(); ++I) {
                        LPath.Append('/');
                        LPath.Append(LRouts[I].Lower());
                    }

                    if (LPath.IsEmpty()) {
                        AConnection->SendStockReply(CReply::not_found);
                        return;
                    }

                    DoFetch(AConnection, LPath);
                }
            } catch (Delphi::Exception::Exception &E) {
                ExceptionToJson(CReply::bad_request, E, LReply->Content);

                AConnection->CloseConnection(true);
                AConnection->SendReply(CReply::ok);

                Log()->Error(APP_LOG_EMERG, 0, E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::DoPost(CHTTPServerConnection *AConnection) {

            auto LRequest = AConnection->Request();
            auto LReply = AConnection->Reply();

            LReply->ContentType = CReply::json;

            CStringList LRouts;
            SplitColumns(LRequest->Location.pathname, LRouts, '/');

            if (LRouts.Count() < 2) {
                AConnection->SendStockReply(CReply::not_found);
                return;
            }

            if (LRouts[1] == _T("v1")) {
                m_Version = 1;
            } else if (LRouts[1] == _T("v2")) {
                m_Version = 2;
            }

            if (LRouts[0] != _T("api") || (m_Version == -1)) {
                AConnection->SendStockReply(CReply::not_found);
                return;
            }

            CString LPath;
            for (int I = 2; I < LRouts.Count(); ++I) {
                LPath.Append('/');
                LPath.Append(LRouts[I].Lower());
            }

            if (LPath.IsEmpty()) {
                AConnection->SendStockReply(CReply::not_found);
                return;
            }

            DoFetch(AConnection, LPath);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAppServer::Heartbeat() {
            auto now = Now();

            if ((now >= m_FixedDate)) {
                m_FixedDate = now + (CDateTime) 30 * 60 / SecsPerDay; // 30 min
                LoadCerts();
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAppServer::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool("worker/AppServer", "enable", true) ? msEnabled : msDisabled;
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