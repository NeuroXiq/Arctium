using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Shared.Mappings.OID;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using static Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID.X509CommonOidsBuilder;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
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

        private static void Initialize()
        {

            //map[SignatureAlgorithm.MD5WithRSAEncryption]  = 1,4),
            //map[SignatureAlgorithm.SHA1WithRSAEncryption] = 1,5),
            map[SignatureAlgorithm.MD2WithRSAEncryption] = pkcs1(2);
            map[SignatureAlgorithm.DSAWithSha1] = pkcs1(3);
            map[SignatureAlgorithm.ECDSAWithSHA1] = pkcs1(1);

            map[SignatureAlgorithm.SHA224WithRSAEncryption] = pkcs1(14);
            map[SignatureAlgorithm.SHA256WithRSAEncryption] = pkcs1(11);
            map[SignatureAlgorithm.SHA384WithRSAEncryption] = pkcs1(12);
            map[SignatureAlgorithm.SHA512WithRSAEncryption] = pkcs1(13);
        }
    }
}
