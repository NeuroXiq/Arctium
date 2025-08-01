namespace Arctium.Protocol.Tls13Impl.Protocol
{
    public enum ServerProtocolCommand
    {
        //BreakLoopWaitForOtherCommand,
        Start,

        Handshake_FirstClientHello,
        Handshake_ClientHello1,
        Handshake_ClientHello2,
        Handshake_ServerHelloNotPsk,
        Handshake_ServerHelloPsk_Dhe,
        Handshake_ServerHelloPsk_Ke,
        Handshake_SendHelloRetryRequestIfNeeded,
        Handshake_EncryptedExtensions,
        Handshake_CertificateRequest,
        Handshake_ServerCertificate,
        Handshake_ServerCertificateVerify,
        Handshake_ServerFinished,
        Handshake_ClientCertificate,
        Handshake_ClientCertificateVerify,
        Handshake_ClientFinished,
        Handshake_HandshakeCompletedSuccessfully,

        Connected_OutsideCommandWaitForAnyProtocolData,
        Connected_LoadApplicationData,
        Connected_WriteApplicationData,
        Connected_StartReceivedPostHandshake,
        Connected_StartPostHandshakeCertificateRequest,

        PostHandshake_NewSessionTicket,
        PostHandshake_Certificate,
        PostHandshake_CertificateVerify,
        PostHandshake_Finished,
        PostHandshake_FinishedProcessingOfPostHandshake,
        PostHandshake_CertificateRequest,
        Connected_OutsideCommandStartPostHandshakeKeyUpdate,
        PostHandshake_SendKeyUpdate,
        PostHandshake_ReceivedKeyUpdate,
        Connected_OutsideCommandClose,
    }
}
