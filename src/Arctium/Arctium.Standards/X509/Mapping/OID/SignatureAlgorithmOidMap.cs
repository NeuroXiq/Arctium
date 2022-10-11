using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Shared.Mappings.OID;
using Arctium.Standards.X509.X509Cert;
using static Arctium.Standards.ASN1.Standards.X509.Mapping.OID.X509CommonOidsBuilder;

namespace Arctium.Standards.ASN1.Standards.X509.Mapping.OID
{
    public static class SignatureAlgorithmOidMap
    {
        static EnumToOidMap<SignatureAlgorithm> map = new EnumToOidMap<SignatureAlgorithm>(nameof(SignatureAlgorithmOidMap));

        public static SignatureAlgorithm Get(ObjectIdentifier oid) => map[oid];
        public static ObjectIdentifier Get(SignatureAlgorithm algorithm) => map[algorithm];


        static SignatureAlgorithmOidMap()
        {
            Initialize();
        }

        static ObjectIdentifier ecdsa(ulong last)
        {
            return new ObjectIdentifier(1, 2, 840, 10045, 4, 3, last);
        }

        private static void Initialize()
        {
            map[SignatureAlgorithm.SHA1WithRSAEncryption] = new ObjectIdentifier(1, 2, 840, 113549, 1, 1, 5);
            map[SignatureAlgorithm.MD2WithRSAEncryption] = pkcs1(2);
            map[SignatureAlgorithm.DSAWithSha1] = pkcs1(3);
            map[SignatureAlgorithm.ECDSAWithSHA1] = pkcs1(1);

            map[SignatureAlgorithm.SHA224WithRSAEncryption] = pkcs1(14);
            map[SignatureAlgorithm.SHA256WithRSAEncryption] = pkcs1(11);
            map[SignatureAlgorithm.SHA384WithRSAEncryption] = pkcs1(12);
            map[SignatureAlgorithm.SHA512WithRSAEncryption] = pkcs1(13);
            map[SignatureAlgorithm.ECDSAWithSHA224] = ecdsa(1);
            map[SignatureAlgorithm.ECDSAWithSHA256] = ecdsa(2);
            map[SignatureAlgorithm.ECDSAWithSHA384] = ecdsa(3);
            map[SignatureAlgorithm.ECDSAWithSHA512] = ecdsa(4);
        }
    }
}
