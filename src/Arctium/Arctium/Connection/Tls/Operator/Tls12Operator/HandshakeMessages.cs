using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    //
    // Copy-paste from tls11operator
    //
    
    class HandshakeMessages
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
