using Arctium.Standards.ArctiumLibShared;
using Arctium.Standards.ASN1.Shared;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.X509.X509Cert
{
    public class X509CertPrivateKey : ChoiceObj<PublicKeyAlgorithmIdentifierType>
    {
        static TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(RSAPrivateKeyCRT), PublicKeyAlgorithmIdentifierType.RSAEncryption),
            new TypeDef(typeof(ECPrivateKey), PublicKeyAlgorithmIdentifierType.ECPublicKey),
        };

        protected override TypeDef[] ChoiceObjConfig => config;

        public X509CertPrivateKey(PublicKeyAlgorithmIdentifierType type, object value) { base.Set(type, value); }

        public X509CertPrivateKey(IArctiumConvertable<RSAPrivateKeyCRT> rsaPrivKey) : this(rsaPrivKey.Convert()) { }
        public X509CertPrivateKey(IArctiumConvertable<ECPrivateKey> ecPrivKey) : this(ecPrivKey.Convert()) { }

        public X509CertPrivateKey(RSAPrivateKeyCRT privKey) : this(PublicKeyAlgorithmIdentifierType.RSAEncryption, privKey) { }
        public X509CertPrivateKey(ECPrivateKey privKey) : this(PublicKeyAlgorithmIdentifierType.ECPublicKey, privKey) { }
    }
}
