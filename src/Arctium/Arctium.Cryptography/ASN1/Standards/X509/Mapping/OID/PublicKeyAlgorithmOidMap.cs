using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.Types;
using Arctium.Shared.Helpers.DataStructures;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class PublicKeyAlgorithmOidMap
    {
        public static ObjectIdentifier Get(PublicKeyAlgorithm publicKeyAlgorithm) => map[publicKeyAlgorithm];
        public static PublicKeyAlgorithm Get(ObjectIdentifier oid) => map[oid];

        static DoubleDictionary<ObjectIdentifier, PublicKeyAlgorithm> map = new DoubleDictionary<ObjectIdentifier, PublicKeyAlgorithm>()
        {
            [PublicKeyAlgorithm.rsaEncryption] = new ObjectIdentifier(1, 2, 840, 113549, 1, 1),
            [PublicKeyAlgorithm.dhpublicnumber] = new ObjectIdentifier(1, 2, 840, 10046, 2, 1),
            [PublicKeyAlgorithm.ecPublicKey] = new ObjectIdentifier(1, 2, 840, 10045, 2, 1),

        };
    }
}
