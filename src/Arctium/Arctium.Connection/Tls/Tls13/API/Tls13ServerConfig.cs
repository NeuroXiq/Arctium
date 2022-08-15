using Arctium.Standards.PKCS1.v2_2;

namespace Arctium.Connection.Tls.Tls13.API
{
    public class Tls13ServerConfig
    {
        public static Tls13ServerConfig Default { get { return BuildDefault(); } }

        public byte[] DerEncodedCertificateBytes;
        public RSAPrivateKey CertificatePrivateKey;

        static Tls13ServerConfig BuildDefault()
        {
            return new Tls13ServerConfig();
        }
    }
}
