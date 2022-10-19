using Arctium.Standards.ASN1.Shared;
using Arctium.Standards.PKCS1.v2_2;
using Arctium.Standards.RFC.RFC5915;

namespace Arctium.Standards.PKCS8.v12
{
    public class PrivateKey : ChoiceObj<PrivateKeyType>
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
    }
}
