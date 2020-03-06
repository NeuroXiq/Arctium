using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class UTF8StringDecoder : IPrimitiveDecoder
    {
        public Tag DecodesTag => BuildInTag.UTF8String;

        public Asn1TaggedType Decode(CodingFrame frame, byte[] buffer, long offset, out long contentLength)
        {
            contentLength = frame.ContentLength.Length;
            if (frame.ContentLength.Length == 0) return new UTF8String("");

            string decoded =  System.Text.Encoding.UTF8.GetString(buffer, (int)offset, (int)contentLength);

            return new UTF8String(decoded);
        }
    }
}
