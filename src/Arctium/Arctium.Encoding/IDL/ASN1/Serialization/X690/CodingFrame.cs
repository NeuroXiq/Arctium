using System;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.DER
{
    public struct CodingFrame
    {
        public int ClassNumber;
        public PCType PC;
        public long TagNumber;
        public ContentLength ContentLength;
        public long FrameLength;
        public Tag Tag;
    }
}
