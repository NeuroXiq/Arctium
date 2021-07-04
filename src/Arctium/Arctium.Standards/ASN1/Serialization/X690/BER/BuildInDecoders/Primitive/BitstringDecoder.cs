using System;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.ASN1.Exceptions;
using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.Exceptions;
using Arctium.Standards.ASN1.Serialization.X690.DER;

namespace Arctium.Standards.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class BitstringDecoder : IX690Decoder<BitString>
    {
        // ommiting first bytes, first byte = num of unused bits
        const int BinaryStringInnerOffset = 1;

        public BitString Decode(byte[] buffer, long offset, long length)
        {
            int unusedBits = buffer[offset];

            if (length == 0)
            {
                if (unusedBits != 0)
                {
                    throw new X690DecoderException(
                        "For the empty bistring first byte of the content shall be set to 0 but current value is {unusedBits}");
                }
                // first byte is always present
                
                return CreateEmptyBitstring();
            }

            if (unusedBits < 0 || unusedBits > 7)
                throw new X690DecoderException($"Value of the unused bits shall be in a range of 0-7 but current value is : {unusedBits}");

            long lengthInBytes = length - 1;
            byte[] bitString = new byte[lengthInBytes];
            MemCpy.Copy(buffer, offset + BinaryStringInnerOffset, bitString, 0, lengthInBytes);

            BitString bsValue = new BitString(bitString, (lengthInBytes * 8) - unusedBits);

            return bsValue;
        }

        private BitString CreateEmptyBitstring()
        {
            BitString empty = new BitString(new byte[0], 0);

            return empty;
        }
    }
}
