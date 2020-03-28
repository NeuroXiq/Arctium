using System;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Shared.Mappings.OID;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class AccessMethodTypeOidMap
    {
        static EnumToOidMap<AccessMethodType> map;

        public static AccessMethodType Get(ObjectIdentifier oid) => map[oid];
        public static ObjectIdentifier Get(AccessMethodType type) => map[type];

        static AccessMethodTypeOidMap()
        {
            CreateMap();
        }

        private static void CreateMap()
        {
            map = new EnumToOidMap<AccessMethodType>(nameof(AccessMethodTypeOidMap))
            {
                [AccessMethodType.CaIssuer] = X509CommonOidsBuilder.idad(2),
                [AccessMethodType.OCSP] = X509CommonOidsBuilder.idad(1),
            };
        }
    }
}
