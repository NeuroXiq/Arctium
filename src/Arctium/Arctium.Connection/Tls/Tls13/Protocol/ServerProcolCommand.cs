namespace Arctium.Connection.Tls.Tls13.Protocol
{
    public enum ServerProcolCommand
    {
        BreakLoopWaitForOtherCommand,

        Start,

        FirstClientHello,
        ClientHello,
        ServerHello,
        EncryptedExtensions,
        CertificateRequest,
        ServerCertificate,
        ServerCertificateVerify,
        ServerFinished,
        ClientCertificate,
        ClientCertificateVerify,

    }
}
