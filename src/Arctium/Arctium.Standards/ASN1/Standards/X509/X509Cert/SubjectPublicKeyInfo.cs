using Arctium.Standards.ASN1.Shared.Exceptions;
using Arctium.Standards.ASN1.Standards.X509.Exceptions;
using System;

namespace Arctium.Standards.ASN1.Standards.X509.X509Cert
{
    public class SubjectPublicKeyInfo
    {
        public PublicKeyAlgorithm AlgorithmType { get; private set; }

        object genericParms;
        object genericPublicKey;

        internal SubjectPublicKeyInfo(PublicKeyAlgorithm algorithm, object parms, object publicKey)
        {
            AlgorithmType = algorithm;
            genericParms = parms;
            genericPublicKey = publicKey;
        }


        public T GetPublicKey<T>()
        {
            Type expectedType = GetExpectedPublicKeyType();
            ASN1CastException.ThrowIfInvalidCast<T, SubjectPublicKeyInfo>(expectedType);

            return (T)genericPublicKey;
        }

        public T GetParms<T>()
        {
            Type expectedType = GetExpectedPublicKeyType();
            ASN1CastException.ThrowIfInvalidCast<T, SubjectPublicKeyInfo>(expectedType);

            return (T)genericPublicKey;
        }

        private Type GetExpectedPublicKeyType()
        {
            switch (AlgorithmType)
            {
                case PublicKeyAlgorithm.RSAEncryption: return typeof(RSAPublicKey);
                case PublicKeyAlgorithm.ECPublicKey: return typeof(byte[]);
                default: throw new X509InternalException("Public key algorithm not found <INTERNAL>");
            }
        }
    }
}
