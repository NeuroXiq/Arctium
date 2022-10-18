using Arctium.Shared.Other;

namespace Arctium.Standards.X509.X509Cert
{
    public class X509CertWithKey
    {
        public X509Certificate Certificate { get; private set; }
        public X509CertPrivateKey PrivateKey { get; private set; }

        public X509CertWithKey(X509Certificate certificate, X509CertPrivateKey privateKey)
        {
            bool privKeyValid = certificate.SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm != privateKey.ValueKey;
            Validation.Argument(privKeyValid, nameof(privateKey), "private key type does not match public key of the certificate");

            Certificate = certificate;
            PrivateKey = privateKey;
        }
    }
}
