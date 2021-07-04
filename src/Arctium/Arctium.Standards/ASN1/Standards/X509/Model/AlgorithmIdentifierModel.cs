using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690;

namespace Arctium.Standards.ASN1.Standards.X509.Model
{
    public class AlgorithmIdentifierModel
    {
        public ObjectIdentifier Algorithm;
        /// <summary>
        /// Optional, defined by <see cref="Algorithm"/>
        /// </summary>
        public byte[] EncodedParameters;


        public AlgorithmIdentifierModel(ObjectIdentifier algorithm, byte[] encodedParameters)
        {
            Algorithm = algorithm;
            EncodedParameters = encodedParameters;
        }
    }
}
