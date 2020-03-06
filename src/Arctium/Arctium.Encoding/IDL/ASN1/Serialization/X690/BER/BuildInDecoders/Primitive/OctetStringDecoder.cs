using System;
using Arctium.DllGlobalShared.Helpers.Buffers;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class OctetStringDecoder : IPrimitiveDecoder
    {
        public Tag DecodesTag => BuildInTag.Octetstring;

        public Asn1TaggedType Decode(CodingFrame frame, byte[] buffer, long offset, out long contentLength)
        {
            long length = frame.ContentLength.Length;
            byte[] stringValue = new byte[length];

            ByteBuffer.Copy(buffer, offset, stringValue, 0, length);

            contentLength = frame.ContentLength.Length;
            return new OctetString(stringValue);

        }
    }
}
