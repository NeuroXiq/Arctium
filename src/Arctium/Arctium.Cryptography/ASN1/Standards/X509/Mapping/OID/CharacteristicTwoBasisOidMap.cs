using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Shared.Helpers.DataStructures;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class CharacteristicTwoBasisOidMap
    {
        const string className = nameof(CharacteristicTwoBasisOidMap);

        public static ObjectIdentifier Get(CharacteristicTwo.BasisType type)
        {
            if (!map.ContainsKey(type))
            {
                throw new KeyNotFoundException($"{className}: " +
                    $"Provided key {type.ToString()} was not found in current mapping");
            }

            return map[type];
        }

        public static CharacteristicTwo.BasisType Get(ObjectIdentifier oid)
        {
            if (!map.ContainsKey(oid))
            {
                throw new KeyNotFoundException($"{className}: " +
                    $"Provided key OID: {oid.ToString()} was not found in current mapping");
            }

            return map[oid];
        }

        static DoubleDictionary<ObjectIdentifier, CharacteristicTwo.BasisType> map = new DoubleDictionary<ObjectIdentifier, CharacteristicTwo.BasisType>()
        {
            [CharacteristicTwo.BasisType.GnBasis] = new ObjectIdentifier(1, 2, 840, 10045, 1, 2, 1, 1),
            [CharacteristicTwo.BasisType.TpBasis] = new ObjectIdentifier(1, 2, 840, 10045, 1, 2, 1, 2),
            [CharacteristicTwo.BasisType.PpBasis] = new ObjectIdentifier(1, 2, 840, 10045, 1, 2, 1, 3),
        };
    }
}
