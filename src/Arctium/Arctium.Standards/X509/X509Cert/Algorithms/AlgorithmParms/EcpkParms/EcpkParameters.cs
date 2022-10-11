using Arctium.Standards.ASN1.Shared;
using Arctium.Standards.X509.X509Cert.Algorithms.AlgorithmParms.EcpkParms;

namespace Arctium.Standards.X509.X509Cert
{
    public class EcpkParameters : ChoiceObj<EcpkParameters.EcpkParmsType>
    {
        static TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(object), EcpkParmsType.ImplicitlyCA, true),
            new TypeDef(typeof(NamedCurve), EcpkParmsType.NamedCurve),
            new TypeDef(typeof(ECParameters), EcpkParmsType.ECParameters),
        };

        public enum EcpkParmsType
        {
            ECParameters,
            NamedCurve,
            ImplicitlyCA
        };

        public EcpkParmsType ParmsType { get; private set; }

        public static EcpkParameters CreateImplicitlyCA() => new EcpkParameters();

        /// <summary>
        /// Creates instance of <see cref="EcpkParameters"/> with a type
        /// <see cref="EcpkParmsType.ImplicitlyCA"/> 
        /// </summary>
        private EcpkParameters() : this(null, EcpkParmsType.ImplicitlyCA) { }
        public EcpkParameters(NamedCurve nameCurveOid) : this(nameCurveOid, EcpkParmsType.NamedCurve) { }
        public EcpkParameters(ECParameters ecParameters) : this(ecParameters, EcpkParmsType.ECParameters) { }

        private EcpkParameters(object value, EcpkParmsType type) : base(config)
        {
            base.Set(type, value);
        }

        public NamedCurve GetNamedCurve() => GetStruct<NamedCurve>();
        public ECParameters GetECParameters() => GetStruct<ECParameters>();
        
        /// <summary>
        /// Does not return anything (no any parameters in this case)
        /// </summary>
        public void GetImplicitlyCA() { }

        // public T GetParams<T>()
        // {
        //     switch (ParmsType)
        //     {
        //         case EcpkParmsType.ECParameters:
        //             if (typeof(ECParameters) == typeof(T))
        //                 return (T)value;
        //             else throw new System.Exception("Expected ECParameters type as generic <T>");
        //         case EcpkParmsType.NamedCurve:
        //             if (typeof(T) != typeof(ObjectIdentifier)) throw new System.Exception("expeceted OID");
        //             return (T)value;
        //         case EcpkParmsType.ImplicitlyCA:
        //             throw new System.Exception("Expecting null as parameters, cannot cast null value from ImplitcliCA");
        //         default:
        //             throw new System.Exception("Unrecognized casing");
        //     }
        // }
    }
}
