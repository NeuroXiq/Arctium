using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class Certificate
    {
        public X509Certificate2 ANS1Certificate;

        public Certificate(X509Certificate2 cert)
        {
            this.ANS1Certificate = cert;
        }
    }
}
