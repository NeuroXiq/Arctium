using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Shared.Mappings.OID;
using Arctium.Standards.X509.X509Cert.Extensions;

namespace Arctium.Standards.ASN1.Standards.X509.Mapping.OID
{
    public static class PolicyQualifierIdOidMap
    {
        static EnumToOidMap<PolicyQualifierId> map = new EnumToOidMap<PolicyQualifierId>(nameof(PolicyQualifierIdOidMap));

        public static PolicyQualifierId Get(ObjectIdentifier oid) => map[oid];
        public static ObjectIdentifier Get(PolicyQualifierId id) => map[id];

        static ObjectIdentifier idqt(ulong last)
        {
            return new ObjectIdentifier(1, 3, 6, 1, 5, 5, 7, 2, last);
        }

        static PolicyQualifierIdOidMap()
        {
            map[PolicyQualifierId.CPS] = idqt(1);
            map[PolicyQualifierId.UserNotice] = idqt(2);
        }
    }
}
