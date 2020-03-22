using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.Shared.Algorithms;
using Arctium.Shared.Helpers.DataStructures;
using System.Collections.Generic;
using static Arctium.Cryptography.Shared.Algorithms.Algorithm;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class SignatureAlgorithmPairOidMap
    {
        static DoubleDictionary<ObjectIdentifier, SignatureAlgorithmPair> map;

        public static ObjectIdentifier GetOid(SignatureAlgorithmPair signatureAlgorithm)
        {
            if (!map.ContainsKey(signatureAlgorithm))
            {
                throw new KeyNotFoundException($"{nameof(SignatureAlgorithmPairOidMap)}: " +
                    $"Provided key {signatureAlgorithm.ToString()} was not found in current mapping");
            }

            return map[signatureAlgorithm];
        }
        public static SignatureAlgorithmPair GetSignatureAlgorithm(ObjectIdentifier oid)
        {
            if (!map.ContainsKey(oid))
            {
                throw new KeyNotFoundException($"{nameof(SignatureAlgorithmPairOidMap)}: " +
                    $"Provided key {oid.ToString()} was not found in current mapping");
            }

            return map[oid];
        }

        static SignatureAlgorithmPairOidMap()
        {
            map = new DoubleDictionary<ObjectIdentifier, SignatureAlgorithmPair>();

            Initialize();
        }

        private static void Initialize()
        {
            // RSA 

            map[Md2Rsa] = new SignatureAlgorithmPair(MD2, RSA);
            map[Md5Rsa] = new SignatureAlgorithmPair(MD5, RSA);
            map[Sha1hRsa] = new SignatureAlgorithmPair(SHA1, RSA);
            map[sha256Rsa] = new SignatureAlgorithmPair(SHA2_256, RSA);

            //DSA
            map[DsaSha1] = new SignatureAlgorithmPair(SHA1, DSA);

            //ECDSA
            map[EcdsaSha1] = new SignatureAlgorithmPair(SHA1, RSA);
        }

        // RSA

        static readonly ObjectIdentifier DsaSha1 = new ObjectIdentifier(1, 2, 840, 10040, 4, 3);
        static readonly ObjectIdentifier Md2Rsa = pkcs1(1);
        static readonly ObjectIdentifier Md5Rsa = pkcs1(4);
        static readonly ObjectIdentifier Sha1hRsa = pkcs1(5);
        static readonly ObjectIdentifier sha256Rsa = new ObjectIdentifier(1, 2, 840, 113549, 1, 1, 11);
        // ECDSA

        static readonly ObjectIdentifier EcdsaSha1 = new ObjectIdentifier(1, 2, 840, 10045, 4, 1);


        // Helpers


        static ObjectIdentifier pkcs1(ulong value)
        {
            return new ObjectIdentifier(1, 2, 840, 113549, 1, value);
        }
    }
}
