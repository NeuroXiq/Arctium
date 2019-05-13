namespace Arctium.Connection.Tls.Operator.Tls11Operator
{
    enum Tls11ClientSendAction
    {
        ClientHello,
        Certificate,
        ClientKeyExchange,
        CertificateVerify,
        ChangeCipherSpec,
        Finished
    }
}
