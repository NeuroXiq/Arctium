using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.DER
{
    public class DerDeserializationResult
    {
        public List<DecodingMetadata> Metadata;
        public List<Asn1TaggedType> RootDecodedValue;
    }
}
