using System;
using Arctium.DllGlobalShared.Helpers.Buffers;
using Arctium.Encoding.IDL.ASN1.Exceptions;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class BitstringDecoder : IPrimitiveDecoder
    {
        public BitstringDecoder()
        {

        }

        public Tag DecodesTag { get { return BuildInTag.Bitstring; } }

        public Asn1TaggedType Decode(CodingFrame frame, byte[] buffer, long offset, out long contentLength)
        {
            if (!frame.ContentLength.IsDefinite) throw new Asn1InternalException("Bitstring of indefinite length is not suppoted now",null,this);

            int unusedBits = buffer[offset];

            if (frame.ContentLength.Length == 0)
            {
                if (unusedBits != 0)
                {
                    throw new X690DecoderException(
                        "For the empty bistring first byte of the content shall be set to 0 but current value is {unusedBits}",frame, this);
                }
                // first byte is always present
                contentLength = 1;
                return CreateEmptyBitstring();
            }

            if (unusedBits < 0 || unusedBits > 7)
                throw new X690DecoderException($"Value of the unused bits shall be in a range of 0-7 but current value is : {unusedBits}", frame, this);

            long lengthInBytes = frame.ContentLength.Length - 1;
            byte[] bitString = new byte[lengthInBytes];
            ByteBuffer.Copy(buffer, offset, bitString, 0, lengthInBytes);

            BitStringValue bsValue = new BitStringValue(bitString, (lengthInBytes * 8) - unusedBits);
            BitString bstring = new BitString(bsValue);

            contentLength = frame.ContentLength.Length;
            return bstring;
        }

        private Asn1TaggedType CreateEmptyBitstring()
        {
            BitString empty = new BitString(new BitStringValue(new byte[0], 0));

            return empty;
        }
    }
}
