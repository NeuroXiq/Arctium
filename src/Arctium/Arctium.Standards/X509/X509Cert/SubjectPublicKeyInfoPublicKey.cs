using Arctium.Standards.ASN1.Shared;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.X509.X509Cert
{
    public class SubjectPublicKeyInfoPublicKey : ChoiceObj<PublicKeyAlgorithmIdentifierType>
    {
        static readonly TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(RSAPublicKey), PublicKeyAlgorithmIdentifierType.RSAEncryption),
            new TypeDef(typeof(byte[]), PublicKeyAlgorithmIdentifierType.ECPublicKey)
        };

        protected override TypeDef[] ChoiceObjConfig => config;

        public PublicKeyAlgorithmIdentifierType Algorithm { get { return base.ValueKey.Value; } }

        public SubjectPublicKeyInfoPublicKey(RSAPublicKey publicKey) : this(PublicKeyAlgorithmIdentifierType.RSAEncryption, publicKey) { }

        public SubjectPublicKeyInfoPublicKey(PublicKeyAlgorithmIdentifierType id, object publicKey)
        {
            base.Set(id, publicKey);
        }
    }
}