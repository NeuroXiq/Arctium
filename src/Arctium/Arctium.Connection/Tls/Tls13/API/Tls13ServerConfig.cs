using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Standards.PKCS1.v2_2;

namespace Arctium.Connection.Tls.Tls13.API
{
    public class Tls13ServerConfig
    {
        public bool UseNewSessionTicketPsk { get; internal set; }
        internal CipherSuite[] CipherSuites;

        public byte[] DerEncodedCertificateBytes;
        public RSAPrivateKey CertificatePrivateKey;
        public string RSAPrivateKeyString;

        public static Tls13ServerConfig DefaultUnsafe(byte[] certBytes, RSAPrivateKey privateKey)
        {
            var c = new Tls13ServerConfig();

            c.DerEncodedCertificateBytes = certBytes;
            c.CertificatePrivateKey = privateKey;

            c.UseNewSessionTicketPsk = true;
            c.CipherSuites = new CipherSuite[]
                {
                    CipherSuite.TLS_AES_256_GCM_SHA384
                };

            return c;
        }
    }
}
