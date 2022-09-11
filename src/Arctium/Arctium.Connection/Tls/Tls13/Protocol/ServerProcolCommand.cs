namespace Arctium.Connection.Tls.Tls13.Protocol
{
    public enum ServerProcolCommand
    {
        BreakLoopWaitForOtherCommand,

        Start,

        FirstClientHello,
        ClientHello,
        ServerHelloNotPsk,
        ServerHelloPsk,
        EncryptedExtensions,
        CertificateRequest,
        ServerCertificate,
        ServerCertificateVerify,
        ServerFinished,
        ClientCertificate,
        ClientCertificateVerify,
        ClientFinished
    }
}
