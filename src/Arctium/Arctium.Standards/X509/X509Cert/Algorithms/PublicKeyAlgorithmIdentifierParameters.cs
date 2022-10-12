using Arctium.Standards.ASN1.Shared;

namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    public class PublicKeyAlgorithmIdentifierParameters : ChoiceObj<PublicKeyAlgorithmIdentifierParametersType>
    {
        static readonly TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(EcpkParameters), PublicKeyAlgorithmIdentifierParametersType.EcpkParameters),
            new TypeDef(typeof(DomainParameters), PublicKeyAlgorithmIdentifierParametersType.DomainParameters)
        };

        protected override TypeDef[] ChoiceObjConfig => config;

        public PublicKeyAlgorithmIdentifierParameters(PublicKeyAlgorithmIdentifierParametersType type, object value)
        {
            base.Set(type, value);
        }

        public PublicKeyAlgorithmIdentifierParameters(EcpkParameters ecpkParams) : this(PublicKeyAlgorithmIdentifierParametersType.EcpkParameters, ecpkParams) { }
        public PublicKeyAlgorithmIdentifierParameters(DomainParameters domainParams) : this(PublicKeyAlgorithmIdentifierParametersType.DomainParameters, domainParams) { }
    }
}
