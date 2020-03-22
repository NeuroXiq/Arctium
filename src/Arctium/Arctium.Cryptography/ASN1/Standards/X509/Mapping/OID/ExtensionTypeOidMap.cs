using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Shared.Helpers.DataStructures;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class ExtensionTypeOidMap
    {
        public static ObjectIdentifier Get(ExtensionType type)
        {
            if (!map.ContainsKey(type))
            {
                throw new KeyNotFoundException($"{nameof(ExtensionTypeOidMap)}: " +
                    $"Provided key {type.ToString()} was not found in current mapping");
            }

            return map[type];
        }

        public static ExtensionType Get(ObjectIdentifier oid)
        {
            if (!map.ContainsKey(oid))
            {
                throw new KeyNotFoundException($"{nameof(ExtensionTypeOidMap)}: " +
                    $"Provided key OID: {oid.ToString()} was not found in current mapping");
            }

            return map[oid];
        }

        static ObjectIdentifier idce(ulong last)
        {
            return new ObjectIdentifier(2, 5, 29, last);
        }

        static DoubleDictionary<ObjectIdentifier, ExtensionType> map = new DoubleDictionary<ObjectIdentifier, ExtensionType>()
        {
            [ExtensionType.AuthorityKeyIdentifier] = idce(35),
            [ExtensionType.SubjectKeyIdentifier] = idce(14),
            [ExtensionType.SubjectAltName] = idce(17),
            [ExtensionType.KeyUsage] = idce(15),
            [ExtensionType.ExtendedKeyUsage] = idce(37),
            [ExtensionType.CRLDistributionPoints] = idce(31)
        };
    }
}
