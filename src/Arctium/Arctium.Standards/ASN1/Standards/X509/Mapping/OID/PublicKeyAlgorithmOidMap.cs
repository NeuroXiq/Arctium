using Arctium.Standards.ASN1.Shared.Mappings.OID;
using Arctium.Standards.ASN1.Standards.X509.X509Cert;
using static Arctium.Standards.ASN1.Standards.X509.X509Cert.PublicKeyAlgorithm;
using static Arctium.Standards.ASN1.Standards.X509.Mapping.OID.X509CommonOidsBuilder;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.ASN1.Standards.X509.Mapping.OID
{
    public static class PublicKeyAlgorithmOidMap
    {
        static EnumToOidMap<PublicKeyAlgorithm> map = new EnumToOidMap<PublicKeyAlgorithm>(nameof(PublicKeyAlgorithm));

        public static PublicKeyAlgorithm Get(ObjectIdentifier oid) => map[oid];
        public static ObjectIdentifier Get(PublicKeyAlgorithm algorithm) => map[algorithm];

        static PublicKeyAlgorithmOidMap()
        {
            Initialize();
        }

        private static void Initialize()
        {
            map[RSAEncryption] = pkcs1(1);
            map[ECPublicKey] = new ObjectIdentifier(1, 2, 840, 10045, 2, 1);
        }
    }
}
