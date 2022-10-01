namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    public enum ServerProcolCommand
    {
        //BreakLoopWaitForOtherCommand,
        Start,

        Handshake_FirstClientHello,
        Handshake_ClientHello1,
        Handshake_HelloRetryRequest,
        Handshake_ClientHello2,
        Handshake_ServerHelloNotPsk,
        Handshake_ServerHelloPsk,
        Handshake_EncryptedExtensions,
        Handshake_CertificateRequest,
        Handshake_ServerCertificate,
        Handshake_ServerCertificateVerify,
        Handshake_ServerFinished,
        Handshake_ClientCertificate,
        Handshake_ClientCertificateVerify,
        Handshake_ClientFinished,
        Handshake_HandshakeCompletedSuccessfully,

        Connected_LoadApplicationData,
        Connected_WriteApplicationData,

        PostHandshake_NewSessionTicket,

        LoadApplicationDataNotReceivedApplicationDataContent,
    }
}
