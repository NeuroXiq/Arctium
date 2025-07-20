using Arctium.Standards.ASN1.Shared;

namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    public class SignatureValue : ChoiceObj<SignatureValueType>
    {
        static TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(EcdsaSigValue), SignatureValueType.EcdsaSigValue),
            new TypeDef(typeof(byte[]), SignatureValueType.NotDefined_RawBytes)
        };

        protected override TypeDef[] ChoiceObjConfig => config;

        public SignatureValue(EcdsaSigValue ecdsaSigValue) : this(SignatureValueType.EcdsaSigValue, ecdsaSigValue) { }
        public SignatureValue(byte[] signatureRawBytes) : this(SignatureValueType.NotDefined_RawBytes, signatureRawBytes) { }

        public SignatureValue(SignatureValueType type, object valueObj)
        {
            base.Set(type, valueObj);
        }
    }
}
