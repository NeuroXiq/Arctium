using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.RFC.RFC5915;

namespace Arctium.Standards.RFC
{
    public class RFC5915_ECPrivateKey
    {
        /// <summary>
        /// decodes RFC5915 der encoded ''ECPrivateKey ::= SEQUENCE structure ''
        /// ignoring [0] parameters OPTIONAL, [1] public key OPTIONAL (todo implement)
        /// </summary>
        /// <param name="privateKeyDerBytes">Der encoded  '' ECPrivateKey ::= SEQUENCE '' as standard specifies </param>
        /// <returns>Parsed DER bytes into object</returns>
        public static EllipticCurvePrivateKey DerDecode(byte[] privateKeyDerBytes)
        {
            var decoding = DerDeserializer.Deserialize2(privateKeyDerBytes, 0);

            long version = decoding.DerTypeDecoder.Integer(decoding.Root[0]).ToLong();
            byte[] privateKey = decoding.DerTypeDecoder.OctetString(decoding.Root[1]).Value;

            // TODO rfc5915 EC PUBLIC KEY ~related PKCS8, implement other tags
            // [0] parameters OPTIONAL, [1] public key OPTIONAL ignoring for not

            return new EllipticCurvePrivateKey(version, privateKey);
        }
    }
}
