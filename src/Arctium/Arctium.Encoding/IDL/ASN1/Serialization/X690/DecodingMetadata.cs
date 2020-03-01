using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690
{
    public class DecodingMetadata
    {
        public CodingFrame Frame;
        public long Offset;
        public Asn1TaggedType DecodedType;
    }
}
