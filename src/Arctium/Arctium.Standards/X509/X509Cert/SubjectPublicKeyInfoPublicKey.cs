using Arctium.Standards.ASN1.Shared;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.X509.X509Cert
{
    public class SubjectPublicKeyInfoPublicKey : ChoiceObj<AlgorithmIdentifierType>
    {
        static readonly TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(RSAPublicKey), AlgorithmIdentifierType.RSAEncryption),
            new TypeDef(typeof(byte[]), AlgorithmIdentifierType.ECPublicKey)
        };

        protected override TypeDef[] ChoiceObjConfig => config;

        public AlgorithmIdentifierType Algorithm { get { return base.ValueKey.Value; } }

        public SubjectPublicKeyInfoPublicKey(RSAPublicKey publicKey) : this(AlgorithmIdentifierType.RSAEncryption, publicKey) { }

        public SubjectPublicKeyInfoPublicKey(AlgorithmIdentifierType id, object publicKey)
        {
            base.Set(id, publicKey);
        }
    }
}