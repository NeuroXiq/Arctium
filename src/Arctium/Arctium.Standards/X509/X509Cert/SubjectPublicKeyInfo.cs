using Arctium.Standards.ASN1.Shared;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.X509.X509Cert
{
    public class SubjectPublicKeyInfo
    {
        public AlgorithmIdentifier AlgorithmIdentifier { get; private set; }
        public SubjectPublicKeyInfoPublicKey PublicKey { get; private set; }

        public SubjectPublicKeyInfo(AlgorithmIdentifier algorithmIdentifier,
            SubjectPublicKeyInfoPublicKey publicKey)
        {
            AlgorithmIdentifier = algorithmIdentifier;
            PublicKey = publicKey;
        }


        //public SubjectPublicKeyInfoParameters Parameters { get; private set; }
        //public SubjectPublicKeyInfoPublicKey PublicKey { get; private set; }

        //public SubjectPublicKeyInfo(SubjectPublicKeyInfoPublicKey publicKey, SubjectPublicKeyInfoParameters parameters)
        //{
        //    Parameters = parameters;
        //    PublicKey = publicKey;
        //}

        // public RSAPublicKey GetRSAPublicKey() => Get<RSAPublicKey>();
        // public byte[] GetECPublicKey() => Get<byte[]>();
    }
}
