using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Model
{
    public class AlgorithmIdentifier
    {
        public ObjectIdentifier Algorithm;
        /// <summary>
        /// Optional, defined by <see cref="Algorithm"/>
        /// </summary>
        public Asn1TaggedType Parameters;


        public AlgorithmIdentifier(ObjectIdentifier algorithm, Asn1TaggedType parameters)
        {
            Algorithm = algorithm;
            Parameters = parameters;
        }
    }
}
