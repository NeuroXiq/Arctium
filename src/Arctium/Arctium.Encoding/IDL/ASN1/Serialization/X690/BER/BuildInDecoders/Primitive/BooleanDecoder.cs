using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    class BooleanDecoder : IPrimitiveDecoder
    {
        public Tag DecodesTag => BuildInTag.Boolean;

        public Asn1TaggedType Decode(CodingFrame frame, byte[] buffer, long offset, out long contentLength)
        {
            if (frame.ContentLength.Length != 1)
            {
                string length = frame.ContentLength.IsDefinite ? frame.ContentLength.Length.ToString() : "indefinite";

                throw new X690DecoderException(
                    "Invalid BER-encoding of the boolean value.\n" +
                    $"Value shall be encoded as an 1-byte value but current content length is {length}",
                    frame,this);
            }

            contentLength = 1;
            bool booleanValue = buffer[offset] > 0;

            return new Boolean(booleanValue);
        }
    }
}
