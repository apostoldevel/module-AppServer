/*++

Program name:

  Apostol Web Service

Module Name:

  AppServer.hpp

Notices:

  Module: Application Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#ifndef APOSTOL_APPSERVER_HPP
#define APOSTOL_APPSERVER_HPP
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CAppServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CAppServer: public CApostolModule {
        private:

            CStringList m_CacheList;

            CDateTime m_FixedDate;

            void InitMethods() override;

            void LoadCerts();
            void UpdateCacheList();

            static void AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload);

            void QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E);

            static bool CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization);

            static int CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError = false);
            static CHTTPReply::CStatusType ErrorCodeToStatus(int ErrorCode);

            static void ReplyError(CHTTPServerConnection *AConnection, CHTTPReply::CStatusType ErrorCode, const CString &Message);

        protected:

            void DoGet(CHTTPServerConnection *AConnection) override;
            void DoPost(CHTTPServerConnection *AConnection);

            void DoFetch(CHTTPServerConnection *AConnection, const CString& Path);

            void DoPostgresQueryExecuted(CPQPollQuery *APollQuery) override;
            void DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) override;

        public:

            explicit CAppServer(CModuleProcess *AProcess);

            ~CAppServer() override = default;

            static class CAppServer *CreateModule(CModuleProcess *AProcess) {
                return new CAppServer(AProcess);
            }

            CString VerifyToken(const CString &Token);

            bool CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization);

            void UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &Path, const CString &Payload,
                const CString &Agent, const CString &Host);

            void AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization,
                const CString &Path, const CString &Payload, const CString &Agent, const CString &Host);

            void SignedFetch(CHTTPServerConnection *AConnection, const CString &Path, const CString &Payload,
                const CString &Session, const CString &Nonce, const CString &Signature, const CString &Agent,
                const CString &Host, long int ReceiveWindow = 5000);

            static CString GetSession(CHTTPRequest *ARequest);
            static bool CheckSession(CHTTPRequest *ARequest, CString &Session);

            static bool CacheAge(const CString &FileName);
            CString GetCacheFile(const CString &Session, const CString &Path, const CString &Payload);

            CStringList &CacheList() { return m_CacheList; };
            const CStringList &CacheList() const { return m_CacheList; };

            void Heartbeat() override;

            bool Enabled() override;

            bool CheckLocation(const CLocation &Location) override;

        };
    }
}

using namespace Apostol::Workers;
}
#endif //APOSTOL_APPSERVER_HPP
