using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.Types;
using Arctium.Shared.Helpers.DataStructures;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class PublicKeyAlgorithmOidMap
    {
        public static ObjectIdentifier Get(PublicKeyAlgorithm publicKeyAlgorithm)
        {
            if (!map.ContainsKey(publicKeyAlgorithm))
            {
                throw new KeyNotFoundException($"{nameof(PublicKeyAlgorithmOidMap)}: " +
                    $"Provided key {publicKeyAlgorithm.ToString()} was not found in current mapping");
            }

            return map[publicKeyAlgorithm];
        }
        public static PublicKeyAlgorithm Get(ObjectIdentifier oid)
        {
            if (!map.ContainsKey(oid))
            {
                throw new KeyNotFoundException($"{nameof(PublicKeyAlgorithmOidMap)}: " +
                    $"Provided key OID: {oid.ToString()} was not found in current mapping");
            }

            return map[oid];
        }

        static DoubleDictionary<ObjectIdentifier, PublicKeyAlgorithm> map = new DoubleDictionary<ObjectIdentifier, PublicKeyAlgorithm>()
        {
            [PublicKeyAlgorithm.rsaEncryption] = new ObjectIdentifier(1, 2, 840, 113549, 1, 1),
            [PublicKeyAlgorithm.dhpublicnumber] = new ObjectIdentifier(1, 2, 840, 10046, 2, 1),
            [PublicKeyAlgorithm.ecPublicKey] = new ObjectIdentifier(1, 2, 840, 10045, 2, 1),

        };
    }
}
