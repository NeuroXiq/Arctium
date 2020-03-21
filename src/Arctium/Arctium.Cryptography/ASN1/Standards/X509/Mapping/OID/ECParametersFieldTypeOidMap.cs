using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.Types;
using Arctium.Shared.Helpers.DataStructures;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class ECParametersFieldTypeOidMap
    {
        public static ObjectIdentifier Get(ECParameters.FieldType type) => map[type];
        public static ECParameters.FieldType Get(ObjectIdentifier oid) => map[oid];

        static DoubleDictionary<ObjectIdentifier, ECParameters.FieldType> map = new DoubleDictionary<ObjectIdentifier, ECParameters.FieldType>()
        {
            [ECParameters.FieldType.PrimeField] = new ObjectIdentifier(1, 2, 840, 10045, 1, 1),
            [ECParameters.FieldType.CharacteristicTwoField] = new ObjectIdentifier(1, 2, 840, 10045, 1, 2),

        };
    }
}
