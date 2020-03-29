using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;
using Arctium.Shared.Helpers.DataStructures;
using System.Collections.Generic;
using static Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID.X509CommonOidsBuilder;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class ExtensionTypeOidMap
    {
        public static bool Contains(ExtensionType type) => map.ContainsKey(type);
        public static bool Contains(ObjectIdentifier oid) => map.ContainsKey(oid);

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

        static DoubleDictionary<ObjectIdentifier, ExtensionType> map = new DoubleDictionary<ObjectIdentifier, ExtensionType>()
        {
            [ExtensionType.AuthorityKeyIdentifier] = idce(35),
            [ExtensionType.SubjectKeyIdentifier] = idce(14),
            [ExtensionType.SubjectAltName] = idce(17),
            [ExtensionType.KeyUsage] = idce(15),
            [ExtensionType.ExtendedKeyUsage] = idce(37),
            [ExtensionType.CRLDistributionPoints] = idce(31),
            [ExtensionType.CertificatePolicy] = idce(32),
            [ExtensionType.AuthorityInfoAccess] = idpe(1),
            [ExtensionType.BasicConstraints] = idce(19),
            [ExtensionType.SCTL] = new ObjectIdentifier(1, 3, 6, 1, 4, 1, 11129, 2, 4, 2),



            //[ExtensionType.KeyIdentifier] = null;
            //[ExtensionType.BasicConstraint
            //[ExtensionType.NameConstraint
            //[ExtensionType.InhibitAntipolicy
            //[ExtensionType.SubjectAlternativeName
            //[ExtensionType.Authority,
            //[ExtensionType.Policy,


        };
    }
}
