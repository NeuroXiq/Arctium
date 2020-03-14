using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Model
{
    public class AlgorithmIdentifierModel
    {
        public ObjectId Algorithm;
        /// <summary>
        /// Optional, defined by <see cref="Algorithm"/>
        /// </summary>
        public Asn1TaggedType Parameters;


        public AlgorithmIdentifierModel(ObjectId algorithm, Asn1TaggedType parameters)
        {
            Algorithm = algorithm;
            Parameters = parameters;
        }
    }
}
