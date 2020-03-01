using Arctium.DllGlobalShared.Helpers.Buffers;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using System;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class OidDecoder : IPrimitiveDecoder
    {
        const byte ContinueSubidentifier = 0x80;

        private Tag tag = BuildInTag.ObjectIdentifier;

        public Tag DecodesTag { get { return tag; } }

        public Asn1TaggedType Decode(CodingFrame frame, byte[] buffer, long offset, out long contentLength)
        {
            long length = frame.ContentLength.Length;
            long i = offset;
            List<OidSubidentifier> subi = new List<OidSubidentifier>();
            List<byte> curData = new List<byte>();

            int subLength = 1;

            while (i < offset + length)
            {
                while((buffer[i + subLength - 1] & ContinueSubidentifier) > 0)
                {
                    if (i + subLength > offset + length) throw new X690DecoderException($"Invalid encoded OID at {offset} at position {i}." +
                                    " Length exceed encoded expected length encoded in frame.", this);
                    subLength++;
                }

                OidSubidentifier subidentifier = ConvertToOidSubidentifier(buffer, i, subLength);
                subi.Add(subidentifier);

                i += subLength;
                subLength = 1;
            }

            contentLength = i - offset;
            return new ObjectIdentifier(subi.ToArray());
        }

        private OidSubidentifier ConvertToOidSubidentifier(byte[] buffer, long offset, int subLength)
        {
            // every first bit is removed from bit string
            // round to bytes
            int length = ((((8 * subLength) - 1) - subLength) / 8) + 1;

            byte[] converted = new byte[length];

            int freeBits = 7;

            for (long i = subLength - 1; i >= 0; i--)
            {
                if (freeBits == 7)
                {
                    converted[i] = (byte)(buffer[offset + i] & 0x7F);
                    freeBits = 1;
                    continue;
                }

                converted[i + 1] |= (byte)(buffer[offset + i] << (8 - freeBits));
                converted[i] |= (byte)((buffer[offset + i] & 0x7F) >> freeBits);

                freeBits++;
            }

            int bitLength = (8 * subLength) - subLength;

            return new OidSubidentifier(converted);

        }
    }
}
