using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.DER
{
    public class DerDecodingResult
    {
        public List<DecodingMetadata> Metadata;
        public object DecodedValue;
    }
}
