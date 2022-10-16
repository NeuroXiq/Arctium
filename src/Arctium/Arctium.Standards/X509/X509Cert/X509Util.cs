using Arctium.Cryptography.Utils;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.X509.X509Cert.Algorithms;
using System.Numerics;

namespace Arctium.Standards.X509.X509Cert
{
    public class X509Util
    {
        //public static HashFunctionId SubjectPublicKeyHashFunctionId(X509Certificate cert)
        //{
        //    var hashFunc = cert.
        //}

        public static Arctium.Cryptography.Ciphers.RSA.RSAPublicKey GetRSAPublicKeyDefault(X509Certificate certificate)
        {
            var algorithm = certificate.SubjectPublicKeyInfo.AlgorithmIdentifier;

            Validation.EnumEqualTo(algorithm.Algorithm, PublicKeyAlgorithmIdentifierType.RSAEncryption, "certificate.SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm");

            var x509PublicKey = certificate.SubjectPublicKeyInfo.PublicKey.Get<RSAPublicKey>();
            var pubExponent = new BigInteger(x509PublicKey.PublicExponent, true, true);
            var modulus = new BigInteger(x509PublicKey.Modulus, true, true);

            var defaultPubKey = new Arctium.Cryptography.Ciphers.RSA.RSAPublicKey(modulus, pubExponent);

            return defaultPubKey;
        }

        public static EcdsaSigValue ASN1_DerDecodeEcdsaSigValue(byte[] derEncodedBytes)
        {
            var decodeCtx = DerDeserializer.Deserialize2(derEncodedBytes, 0);
            MemDump.HexDump(derEncodedBytes);

            var rBytes = decodeCtx.DerTypeDecored.Integer(decodeCtx.Current[0]).BinaryValue;
            var sBytes = decodeCtx.DerTypeDecored.Integer(decodeCtx.Current[1]).BinaryValue;

            return new EcdsaSigValue(rBytes, sBytes);
        }

        public static void ASN1_DerEncodeEcdsaSigValue(EcdsaSigValue ecdsaSigValue)
        {

        }
    }
}
