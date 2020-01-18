using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Tls12.Operator.Tls11Operator
{
    class HandshakeMessages11
    {
        public ClientHello ClientHello;
        public ServerHello ServerHello;
        public Certificate ServerCertificate;
        public ServerKeyExchange ServerKeyExchage;
        public CertificateRequest CertificateRequset;
        public ServerHelloDone ServerHelloDone;

        public Certificate ClientCertificate;
        public ClientKeyExchange ClientKeyExchange;
        public CertificateVerify CertificateVerify;

        public Finished ClientFinished;
        public Finished ServerFinished;
    }
}
