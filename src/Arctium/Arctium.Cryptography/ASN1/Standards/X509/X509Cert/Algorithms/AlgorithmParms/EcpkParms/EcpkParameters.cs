using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public struct EcpkParameters
    {
        public enum EcpkParmsType
        {
            ECParameters,
            NamedCurve,
            ImplicitlyCA
        };

        public EcpkParmsType ChoiceType { get; private set; }

        private object value;

        public T GetParams<T>()
        {
            switch (ChoiceType)
            {
                case EcpkParmsType.ECParameters:
                    if (typeof(ECParameters) == typeof(T))
                        return (T)value;
                    else throw new System.Exception("Expected ECParameters type as generic <T>");
                    break;
                case EcpkParmsType.NamedCurve:
                    if (typeof(T) != typeof(ObjectIdentifier)) throw new System.Exception("expeceted OID");
                    return (T)value;
                case EcpkParmsType.ImplicitlyCA:
                    throw new System.Exception("Expecting null as parameters, cannot cast null value from ImplitcliCA");
                default:
                    throw new System.Exception("Unrecognized casing");
            }
        }
    }
}
