using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class NullDecoder : IPrimitiveDecoder
    {
        public NullDecoder()
        {
        }

        public Tag DecodesTag { get { return BuildInTag.Null; } }

        public Asn1TaggedType Decode(CodingFrame frame, byte[] buffer, long offset, out long contentLength)
        {
            contentLength = 0;
            return new Null();
        }
    }
}
