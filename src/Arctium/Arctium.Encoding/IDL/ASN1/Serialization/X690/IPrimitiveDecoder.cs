using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690
{
    public interface IPrimitiveDecoder
    {
        Tag DecodesTag { get; }

        Asn1TaggedType Decode(CodingFrame frame, byte[] buffer, long offset, out long contentLength);
    }
}
