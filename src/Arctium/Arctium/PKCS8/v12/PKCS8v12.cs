using Arctium.Shared;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders;
using Arctium.Standards.ASN1.Standards.X509.Mapping;
using Arctium.Standards.FileFormat.PEM;
using Arctium.Standards.PKCS1.v2_2.ASN1;
using Arctium.Standards.PKCS8.v12.ASN1;
using Arctium.Standards.RFC;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.PKCS8.v12
{
    public class PKCS8v12
    {
        const string PEMBeginLabel = "PRIVATE KEY";
        const string PEMEncryptedBeginLabel = "ENCRYPTED PRIVATE KEY";

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pemFile"></param>
        /// <param name="key">If encrypted, key to decrypt otherwise null and file is not interpreted as encrypted</param>
        /// <returns></returns>
        public static PrivateKeyInfo FromPem(PemFile pemFile, byte[] key = null)
        {
            if (pemFile.BeginLabel == PEMEncryptedBeginLabel)
                Validation.NotNull(key, nameof(key), "PEM file starts with encrypted label but key is null. Key must be provided");

            Validation.Argument(PEMBeginLabel != pemFile.BeginLabel && pemFile.BeginLabel != PEMEncryptedBeginLabel,
                nameof(pemFile),
                $"Invalid pem file BEGIN label. Only can be: '{PEMBeginLabel}' or '{PEMEncryptedBeginLabel}'");

            return DerDeserialize(pemFile.DecodedData);
        }

        static PrivateKeyInfo DerDeserialize(byte[] bytes, byte[] key = null)
        {
            return DecodeModel(bytes);
        }

        static PrivateKeyInfo DecodeModel(byte[] bytes)
        {
            var decodedCtx = DerDeserializer.Deserialize2(bytes, 0);
            var root = decodedCtx.Current;
            var typeDecode = decodedCtx.DerTypeDecoder;
            PrivateKeyInfoModel m = new PrivateKeyInfoModel();

            decodedCtx.Current = root[1];

            m.Version = typeDecode.Integer(root[0]);
            m.PrivateKeyAlgorithmIdentifier = AlgorithmIdentifierModelDecoder.Decode(decodedCtx);
            m.PrivateKey = typeDecode.OctetString(root[2]);

            var algorithmIdentifier = SubjectPublicKeyInfoMapper.MapAlgorithmIdentifier(m.PrivateKeyAlgorithmIdentifier);
            var version = m.Version.ToLong(); // no idea what is valid range (fit in long?)

            PrivateKey privateKey = DecodePrivateKeyOctets(algorithmIdentifier, m.PrivateKey);

            return new PrivateKeyInfo(version, algorithmIdentifier, privateKey);
        }

        static PrivateKey DecodePrivateKeyOctets(PublicKeyAlgorithmIdentifier algoId, byte[] privateKeyOctets)
        {
            object result = null;
            PrivateKeyType type = PrivateKeyType.EllipticCurve;

            if (algoId.Algorithm == PublicKeyAlgorithmIdentifierType.ECPublicKey)
            {
                result = RFC5915_ECPrivateKey.DerDecode(privateKeyOctets);
            }
            else if (algoId.Algorithm == PublicKeyAlgorithmIdentifierType.RSAEncryption)
            {
                var pkcs1decoder = new PKCS1DerDecoder();
                result = pkcs1decoder.DecodeRsaPrivateKey(privateKeyOctets);

                type = PrivateKeyType.RSAEncryption;
            }
            else throw new System.Exception("unknow private key bytes unable to decode");

            return new PrivateKey(type, result);
        }
    }
}
