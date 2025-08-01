using Arctium.Shared;
using Arctium.Standards.ArctiumLibShared;
using Arctium.Standards.ASN1.Shared;
using Arctium.Standards.PKCS1.v2_2;
using Arctium.Standards.RFC.RFC5915;
using Arctium.Standards.X509.X509Cert;

namespace Arctium.Standards.PKCS8.v12
{
    public class PrivateKey : ChoiceObj<PrivateKeyType>, IArctiumConvertable<X509CertPrivateKey>
    {
        static TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(EllipticCurvePrivateKey), PrivateKeyType.EllipticCurve),
            new TypeDef(typeof(RSAPrivateKey), PrivateKeyType.RSAEncryption)
        };

        protected override TypeDef[] ChoiceObjConfig => config;

        public PrivateKey(PrivateKeyType type, object privKey) { base.Set(type, privKey); }

        public EllipticCurvePrivateKey Choice_EllipticCurvePrivateKey() => base.Get<EllipticCurvePrivateKey>();
        public RSAPrivateKey Choice_RSAPrivateKey() => base.Get<RSAPrivateKey>();

        public X509CertPrivateKey Convert()
        {
            if (ValueKey == PrivateKeyType.RSAEncryption) return new X509CertPrivateKey(Choice_RSAPrivateKey());
            else if (ValueKey == PrivateKeyType.EllipticCurve) return new X509CertPrivateKey(Choice_EllipticCurvePrivateKey());

            Validation.NotSupported();

            return null;
        }
    }
}
