using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.Types;

using Arctium.Shared.Helpers.DataStructures;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class CharacteristicTwoBasisOidMap
    {
        public static ObjectIdentifier Get(CharacteristicTwo.BasisType type) => map[type];
        public static CharacteristicTwo.BasisType Get(ObjectIdentifier oid) => map[oid];

        static DoubleDictionary<ObjectIdentifier, CharacteristicTwo.BasisType> map = new DoubleDictionary<ObjectIdentifier, CharacteristicTwo.BasisType>()
        {
            [CharacteristicTwo.BasisType.GnBasis] = new ObjectIdentifier(1, 2, 840, 10045, 1, 2, 1, 1),
            [CharacteristicTwo.BasisType.TpBasis] = new ObjectIdentifier(1, 2, 840, 10045, 1, 2, 1, 2),
            [CharacteristicTwo.BasisType.PpBasis] = new ObjectIdentifier(1, 2, 840, 10045, 1, 2, 1, 3),
        };
    }
}
