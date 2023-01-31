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

    namespace Module {

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

            void QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E);

            static bool CheckAuthorizationData(const CHTTPRequest &Request, CAuthorization &Authorization);

            static int CheckError(const CJSON &Json, CString &ErrorMessage);
            static CHTTPReply::CStatusType ErrorCodeToStatus(int ErrorCode);

        protected:

            void DoGet(CHTTPServerConnection *AConnection) override;
            void DoPost(CHTTPServerConnection *AConnection);

            void DoFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path);

            void DoPostgresQueryExecuted(CPQPollQuery *APollQuery) override;
            void DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) override;

        public:

            explicit CAppServer(CModuleProcess *AProcess);

            ~CAppServer() override = default;

            static class CAppServer *CreateModule(CModuleProcess *AProcess) {
                return new CAppServer(AProcess);
            }

            CString VerifyToken(const CString &Token);

            int CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization);
            void CheckTokenAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization, COnSocketExecuteEvent && OnContinue);

            void UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, const CString &Agent, const CString &Host);

            void AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization,
                const CString &Method, const CString &Path, const CString &Payload, const CString &Agent, const CString &Host);

            void SignedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, const CString &Session, const CString &Nonce, const CString &Signature,
                const CString &Agent, const CString &Host, long int ReceiveWindow = 5000);

            static CString GetSession(const CHTTPRequest &Request);
            static bool CheckSession(const CHTTPRequest &Request, CString &Session);

            static bool CacheAge(const CString &FileName);
            CString GetCacheFile(const CString &Session, const CString &Path, const CString &Payload);

            CStringList &CacheList() { return m_CacheList; };
            const CStringList &CacheList() const { return m_CacheList; };

            void Heartbeat(CDateTime DateTime) override;

            bool Enabled() override;

            bool CheckLocation(const CLocation &Location) override;

        };
    }
}

using namespace Apostol::Module;
}
#endif //APOSTOL_APPSERVER_HPP
