using Arctium.Shared.Helpers.DataStructures;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.X501.Types;
using System;

namespace Arctium.Standards.X501.Mapping.Oid
{
    public static class AttributeTypeOidMap
    {
        static AttributeTypeOidMap()
        {
        }

        public static ObjectIdentifier Get(AttributeType type) => map[type];
        public static AttributeType Get(ObjectIdentifier oid) => map[oid];

        public static bool Exists(AttributeType type) => map.ContainsKey(type);
        public static bool Exists(ObjectIdentifier oid) => map.ContainsKey(oid);

        // helper, id_at OID have prefix used in all Type mappings
        static ObjectIdentifier idat(ulong append)
        {
            return new ObjectIdentifier(2, 5, 4, append);
        }

        static DoubleDictionary<AttributeType, ObjectIdentifier> map = new DoubleDictionary<AttributeType, ObjectIdentifier>()
        {
            [AttributeType.Surname] = idat(4),
            [AttributeType.GivenName] = idat(42),
            [AttributeType.Initials] = idat(43),
            [AttributeType.GenerationQualifier] = idat(44),
            [AttributeType.CommonName] = idat(3),
            [AttributeType.Locality] = idat(7),
            [AttributeType.StateOrProvinceName] = idat(8),
            [AttributeType.Organization] = idat(10),
            [AttributeType.OrganizationalUnit] = idat(11),
            [AttributeType.Title] = idat(12),
            [AttributeType.DistinguishedNameQualifier] = idat(46),
            [AttributeType.Country] = idat(6),
            [AttributeType.SerialNumber] = idat(41),
            [AttributeType.Pseudonym] = idat(65),
            [AttributeType.DomainComponent] = new ObjectIdentifier(0,9,2342,19200300,100,1,25),
            [AttributeType.Email] = new ObjectIdentifier(1,2,840,113549,1,9,1)
        };
    }
}