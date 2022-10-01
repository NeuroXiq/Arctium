namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    internal enum ClientProtocolCommand
    {
        Start_Connect,

        Handshake_ClientHello,
        Handshake_ServerHello,
        Handshake_EncryptedExtensions,
        Handshake_CertificateRequest,
        Handshake_ServerCertificate,
        Handshake_ServerCertificateVerify,
        Handshake_ServerFinished,
        Handshake_ClientCertificate,
        Handshake_ClientCertificateVerify,
        Handshake_ClientFinished,

        Connected_ReadApplicationData,
        Connected_WriteApplicationData,
    }
}
