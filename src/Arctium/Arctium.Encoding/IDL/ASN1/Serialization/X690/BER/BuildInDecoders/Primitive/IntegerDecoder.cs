using Arctium.DllGlobalShared.Helpers.Binary;
using Arctium.DllGlobalShared.Helpers.Buffers;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using System;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class IntegerDecoder : IPrimitiveDecoder
    {
        Tag tag = BuildInTag.Integer;
        public Tag DecodesTag { get { return tag; } }

        public Asn1TaggedType Decode(CodingFrame frame, byte[] buffer, long offset, out long contentLength)
        {
            if (frame.ContentLength.IsDefinite)
            {
                long length = frame.ContentLength.Length;
                byte[] value = new byte[length];
                ByteBuffer.Copy(buffer, offset, value, 0, length);

                contentLength = length;
                return new Integer(new IntegerValue(value));

            }
            else throw new Exception("not supporter indefinite for intefer");
        }
    }
}
