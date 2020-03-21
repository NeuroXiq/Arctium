using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Shared.Helpers.DataStructures;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    public static class ExtensionTypeOidMap
    {
        public static ObjectIdentifier Get(ExtensionType type) => map[type];
        public static ExtensionType Get(ObjectIdentifier oid) => map[oid];

        static ObjectIdentifier idce(ulong last)
        {
            return new ObjectIdentifier(2, 5, 29, last);
        }

        static DoubleDictionary<ObjectIdentifier, ExtensionType> map = new DoubleDictionary<ObjectIdentifier, ExtensionType>()
        {
            [ExtensionType.AuthorityKeyIdentifier] = idce(35),
        };
    }
}
