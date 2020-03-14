using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690
{
    public class X690DeserializationResult
    {
        public long DecodedBytes;
        public long DecodedTypes;
        public long ConstructorsCount;
        public long PrimitiveCount;

        public List<DecodingMetadata> Metadata;
        public List<Asn1TaggedType> RootDecodedValue;
    }
}
