namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    internal enum ClientProtocolCommand
    {
        Start_Connect,

        Handshake_ClientHello1,
        Handshake_ServerHelloOrHelloRetryRequest,
        Handshake_HelloRetryRequest,
        Handshake_ClientHello2,
        Handshake_ServerHello,
        Handshake_EncryptedExtensions,
        Handshake_CertificateRequest,
        Handshake_ServerCertificate,
        Handshake_ServerCertificateVerify,
        Handshake_ServerFinished,
        Handshake_ClientCertificate,
        Handshake_ClientCertificateVerify,
        Handshake_ClientFinished,
        Handshake_HandshakeCompletedSuccessfully,
        Connected_ReceivedPostHandshakeMessage,

        Connected_ReadApplicationData,
        Connected_WriteApplicationData,

        PostHandshake_ProcessPostHandshakeMessage,
        PostHandshake_FinishedProcessingPostHandshakeMessages,
    }
}
