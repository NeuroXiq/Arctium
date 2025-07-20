using Arctium.Standards.ASN1.Shared;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.X509.X509Cert
{
    public class SubjectPublicKeyInfo
    {
        public PublicKeyAlgorithmIdentifier AlgorithmIdentifier { get; private set; }
        public SubjectPublicKeyInfoPublicKey PublicKey { get; private set; }

        public SubjectPublicKeyInfo(PublicKeyAlgorithmIdentifier algorithmIdentifier,
            SubjectPublicKeyInfoPublicKey publicKey)
        {
            AlgorithmIdentifier = algorithmIdentifier;
            PublicKey = publicKey;
        }
    }
}
