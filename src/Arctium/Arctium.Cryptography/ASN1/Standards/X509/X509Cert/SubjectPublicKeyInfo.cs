using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public class SubjectPublicKeyInfo
    {
        public PublicKeyAlgorithm AlgorithmType { get; private set; }

        public T GetParms<T>() { throw new NotSupportedException(); }

        public T GetPublicKey<T>() { throw new NotSupportedException(); }

        object genericParms;
        object genericPublicKey;

        internal SubjectPublicKeyInfo(PublicKeyAlgorithm algorithm, object parms, object publicKey)
        {
            AlgorithmType = algorithm;
            genericParms = parms;
            genericPublicKey = publicKey;
        }
    }
}
