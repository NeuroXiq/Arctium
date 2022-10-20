using Arctium.Cryptography.Utils;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.X509.X509Cert.Algorithms;
using System;
using System.Linq;
using System.Numerics;

namespace Arctium.Standards.X509.X509Cert
{
    public class X509Util
    {
        //public static HashFunctionId SubjectPublicKeyHashFunctionId(X509Certificate cert)
        //{
        //    var hashFunc = cert.
        //}

        static readonly SignatureAlgorithmType[] ECDSASignatureAlgorithmTypes = new SignatureAlgorithmType[]
        {
            SignatureAlgorithmType.ECDSAWithSHA1,
            SignatureAlgorithmType.ECDSAWithSHA224,
            SignatureAlgorithmType.ECDSAWithSHA256,
            SignatureAlgorithmType.ECDSAWithSHA384,
            SignatureAlgorithmType.ECDSAWithSHA512,
        };

        static readonly SignatureAlgorithmType[] RSAEncryptionSignatureAlgorithmTypes = new SignatureAlgorithmType[]
        {
            SignatureAlgorithmType.MD2WithRSAEncryption,
            SignatureAlgorithmType.SHA1WithRSAEncryption,
            SignatureAlgorithmType.SHA224WithRSAEncryption,
            SignatureAlgorithmType.SHA384WithRSAEncryption,
            SignatureAlgorithmType.SHA512WithRSAEncryption,
            SignatureAlgorithmType.SHA256WithRSAEncryption,
            SignatureAlgorithmType.MD2WithRSAEncryption,
            SignatureAlgorithmType.MD5WithRSAEncryption,
        };

        /// <summary>
        /// If certificate was decoded from DER bytes then this method returns this bytes otherwise throws notsupportedexception.
        /// Converting x509 cert to bytes is valid operation but for now 
        /// serialization of x509 certificate is not implemented, so if certificate was not 
        /// deserialized from bytes but created as an object operation is not supported.
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static byte[] X509CertificateToDerEncodedBytes(X509Certificate certificate)
        {
            if (certificate.DerEncodedBytesDeserializedBytes == null)
                Validation.NotSupported("for now only decoded certificates decoded supported, serialization of created object not supported");

            return certificate.DerEncodedBytesDeserializedBytes;
        }

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

            var rBytes = decodeCtx.DerTypeDecoder.Integer(decodeCtx.Current[0]).BinaryValue;
            var sBytes = decodeCtx.DerTypeDecoder.Integer(decodeCtx.Current[1]).BinaryValue;

            return new EcdsaSigValue(rBytes, sBytes);
        }

        public static byte[] ASN1_DerEncodeEcdsaSigValue(EcdsaSigValue ecdsaSigValue)
        {

        }

        /// <summary>
        /// Returns true if Certificate is signed with ECDSA algorithm.
        /// This is helper method, same can be achiever comparing <see cref="SignatureAlgorithmType"/> or certificate
        /// with all possible ECDSA types
        /// </summary>
        /// <param name="cert">certificate to check for signature algorithm</param>
        /// <returns>True if certificate is signed with ECDSA otherwise false</returns>
        public static bool IsCertSignatureECDSA(X509Certificate cert) => ECDSASignatureAlgorithmTypes.Contains(cert.SignatureAlgorithm.SignatureAlgorithmType);

        /// <summary>
        /// Returns true if Certificate is signed with RSAEncryption algorithm.
        /// This is helper method, same can be achiever comparing <see cref="SignatureAlgorithmType"/> or certificate
        /// with all possible RSAEncryption types
        /// </summary>
        /// <param name="cert">certificate to check for signature algorithm</param>
        /// <returns>True if certificate is signed with RSAEncryption otherwise false</returns>
        public static bool IsCerSignatureRSAEncryption(X509Certificate cert) => RSAEncryptionSignatureAlgorithmTypes.Contains(cert.SignatureAlgorithm.SignatureAlgorithmType);
    }
}
