using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.Types;
using Arctium.Shared.Helpers.DataStructures;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class SignatureAlgorithmOidMap
    {
        public static ObjectIdentifier Get(SignatureAlgorithm signatureAlgorithm)
        {
            if (!map.ContainsKey(signatureAlgorithm))
            {
                throw new KeyNotFoundException($"{nameof(SignatureAlgorithmOidMap)}: " +
                    $"Provided key {signatureAlgorithm.ToString()} was not found in current mapping");
            }

            return map[signatureAlgorithm];
        }
        public static SignatureAlgorithm Get(ObjectIdentifier oid)
        {
            if (!map.ContainsKey(oid))
            {
                throw new KeyNotFoundException($"{nameof(SignatureAlgorithmOidMap)}: " +
                    $"Provided key OID: {oid.ToString()} was not found in current mapping");
            }

            return map[oid];
        }


        public static DoubleDictionary<ObjectIdentifier, SignatureAlgorithm> map = new DoubleDictionary<ObjectIdentifier, SignatureAlgorithm>()
        {
            [SignatureAlgorithm.md2WithRSAEncryption] = new ObjectIdentifier(1, 2, 840, 113549, 1, 1, 2),
            [SignatureAlgorithm.md5WithRSAEncryption] = new ObjectIdentifier(1,2,840,113549,1,1,4),
            [SignatureAlgorithm.sha_1WithRSAEncryption] = new ObjectIdentifier(1,2,840,113549,1,1,5),
            [SignatureAlgorithm.dsaWithSha1] = new ObjectIdentifier(1,2,840,10040,4,3),
            [SignatureAlgorithm.ecdsaWithSHA1] = new ObjectIdentifier(1,2,840,10045,4,1),



        };
    }
}
