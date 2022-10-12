using Arctium.Standards.ASN1.Shared;

namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    public class AlgorithmIdentifierParameters : ChoiceObj<AlgorithmIdentifierParametersType>
    {
        static readonly TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(EcpkParameters), AlgorithmIdentifierParametersType.EcpkParameters),
            new TypeDef(typeof(DomainParameters), AlgorithmIdentifierParametersType.DomainParameters)
        };

        protected override TypeDef[] ChoiceObjConfig => config;

        public AlgorithmIdentifierParameters(AlgorithmIdentifierParametersType type, object value)
        {
            base.Set(type, value);
        }

        public AlgorithmIdentifierParameters(EcpkParameters ecpkParams) : this(AlgorithmIdentifierParametersType.EcpkParameters, ecpkParams) { }
        public AlgorithmIdentifierParameters(DomainParameters domainParams) : this(AlgorithmIdentifierParametersType.DomainParameters, domainParams) { }
    }
}
