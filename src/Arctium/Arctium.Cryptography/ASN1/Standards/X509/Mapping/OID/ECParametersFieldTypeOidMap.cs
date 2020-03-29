using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Shared.Helpers.DataStructures;
using System.Collections.Generic;


namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class ECParametersFieldTypeOidMap
    {
        const string className = nameof(ECParametersFieldTypeOidMap);

        public static ObjectIdentifier Get(ECParameters.FieldType type)
        {
            if (!map.ContainsKey(type))
            {
                throw new KeyNotFoundException($"{className}: " +
                    $"Provided key {type.ToString()} was not found in current mapping");
            }

            return map[type];
        }

        public static ECParameters.FieldType Get(ObjectIdentifier oid)
        {
            if (!map.ContainsKey(oid))
            {
                throw new KeyNotFoundException($"{className}: " +
                    $"Provided key OID: {oid.ToString()} was not found in current mapping");
            }

            return map[oid];
        }

        static DoubleDictionary<ObjectIdentifier, ECParameters.FieldType> map = new DoubleDictionary<ObjectIdentifier, ECParameters.FieldType>()
        {
            [ECParameters.FieldType.PrimeField] = new ObjectIdentifier(1, 2, 840, 10045, 1, 1),
            [ECParameters.FieldType.CharacteristicTwoField] = new ObjectIdentifier(1, 2, 840, 10045, 1, 2),

        };
    }
}
