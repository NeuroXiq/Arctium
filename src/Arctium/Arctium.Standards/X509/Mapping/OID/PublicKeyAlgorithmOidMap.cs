using Arctium.Standards.ASN1.Shared.Mappings.OID;
using static Arctium.Standards.ASN1.Standards.X509.Mapping.OID.X509CommonOidsBuilder;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.ASN1.Standards.X509.Mapping.OID
{
    public static class PublicKeyAlgorithmOidMap
    {
        static EnumToOidMap<AlgorithmIdentifierType> map = new EnumToOidMap<AlgorithmIdentifierType>(nameof(AlgorithmIdentifierType));

        public static AlgorithmIdentifierType Get(ObjectIdentifier oid) => map[oid];
        public static ObjectIdentifier Get(AlgorithmIdentifierType algorithm) => map[algorithm];

        static PublicKeyAlgorithmOidMap()
        {
            Initialize();
        }

        private static void Initialize()
        {
            map[AlgorithmIdentifierType.RSAEncryption] = pkcs1(1);
            map[AlgorithmIdentifierType.ECPublicKey] = new ObjectIdentifier(1, 2, 840, 10045, 2, 1);
        }
    }
}
