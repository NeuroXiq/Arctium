using Arctium.Standards.ASN1.Shared;

namespace Arctium.Standards.X509.X509Cert
{
    public class SubjectPublicKeyInfo : ChoiceObj<AlgorithmIdentifierId>
    {
        static TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(RSAPublicKey), AlgorithmIdentifierId.RSAEncryption),
            new TypeDef(typeof(byte[]), AlgorithmIdentifierId.ECPublicKey),
        };

        public AlgorithmIdentifierId Algorithm { get; private set; }

        // public PublicKeyAlgorithm AlgorithmType { get; private set; }
        // ANY parameters defined by algotype above(todo)
        public object EcpkParameters { get; private set; }

        internal SubjectPublicKeyInfo(AlgorithmIdentifierId algorithm, EcpkParameters parms, object publicKey) : base(config)
        {
            base.Set(algorithm, publicKey);

            Algorithm = algorithm;
            EcpkParameters = parms;
        }

        public RSAPublicKey GetRSAPublicKey() => Get<RSAPublicKey>();
        public byte[] GetECPublicKey() => Get<byte[]>();
    }
}
