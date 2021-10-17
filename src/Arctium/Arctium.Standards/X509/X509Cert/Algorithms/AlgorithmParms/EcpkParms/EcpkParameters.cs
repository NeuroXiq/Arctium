using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.X509.X509Cert
{
    public class EcpkParameters
    {
        public enum EcpkParmsType
        {
            ECParameters,
            NamedCurve,
            ImplicitlyCA
        };

        public EcpkParmsType ParmsType { get; private set; }

        private object value;

        /// <summary>
        /// Creates instance of <see cref="EcpkParameters"/> with a type
        /// <see cref="EcpkParmsType.ImplicitlyCA"/> 
        /// </summary>
        public EcpkParameters()
        {
            ParmsType = EcpkParmsType.ImplicitlyCA;
        }


        public EcpkParameters(ObjectIdentifier nameCurveOid)
        {
            ParmsType = EcpkParmsType.NamedCurve;
            value = nameCurveOid;
        }

        public EcpkParameters(ECParameters ecParameters)
        {
            ParmsType = EcpkParmsType.ECParameters;
            value = ecParameters;
        }

        public T GetParams<T>()
        {
            switch (ParmsType)
            {
                case EcpkParmsType.ECParameters:
                    if (typeof(ECParameters) == typeof(T))
                        return (T)value;
                    else throw new System.Exception("Expected ECParameters type as generic <T>");
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
