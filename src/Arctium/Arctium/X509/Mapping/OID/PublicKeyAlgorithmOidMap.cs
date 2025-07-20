using Arctium.Standards.ASN1.Shared.Mappings.OID;
using static Arctium.Standards.ASN1.Standards.X509.Mapping.OID.X509CommonOidsBuilder;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.ASN1.Standards.X509.Mapping.OID
{
    public static class PublicKeyAlgorithmOidMap
    {
        static EnumToOidMap<PublicKeyAlgorithmIdentifierType> map = new EnumToOidMap<PublicKeyAlgorithmIdentifierType>(nameof(PublicKeyAlgorithmIdentifierType));

        public static PublicKeyAlgorithmIdentifierType Get(ObjectIdentifier oid) => map[oid];
        public static ObjectIdentifier Get(PublicKeyAlgorithmIdentifierType algorithm) => map[algorithm];

        static PublicKeyAlgorithmOidMap()
        {
            Initialize();
        }

        private static void Initialize()
        {
            map[PublicKeyAlgorithmIdentifierType.RSAEncryption] = pkcs1(1);
            map[PublicKeyAlgorithmIdentifierType.ECPublicKey] = new ObjectIdentifier(1, 2, 840, 10045, 2, 1);
        }
    }
}
