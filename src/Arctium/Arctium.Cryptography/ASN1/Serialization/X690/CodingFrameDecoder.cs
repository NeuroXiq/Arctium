using System;
using Arctium.Cryptography.ASN1.Exceptions;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.Serialization.Exceptions;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;

namespace Arctium.Cryptography.ASN1.Serialization.X690
{
    class CodingFrameDecoder
    {
        const byte ClassNumberMask = 0xc0;
        const byte PCMask = 0x20;
        const byte TagNumberMask = 0x1F;
        const byte HighTagNumber = 0x1F;
        const byte MaxTagLength = 64;
        const byte HighTagNumberNotFinalByte = 0x80;
        const byte LengthIndefiniteForm = 0x80;
        const byte LengthLongForm = 0x80;
        const byte DefiniteLongLengthMask = 0x7F;
        const byte MaxDefiniteLongLength = 8;

        public CodingFrame DecodeFrame(byte[] buffer, long offset)
        {
            int classNumber = (buffer[offset] & ClassNumberMask) >> 6;
            PCType pc = (buffer[offset] & PCMask) > 0 ? PCType.Constructed : PCType.Primitive;
            int tagNumberSize;
            long tagNumber = DecodeTagNumber(buffer, offset, out tagNumberSize);
            int lengthSize;
            ContentLength contentLength = DecodeLength(buffer, offset + tagNumberSize + 1, out lengthSize);


            CodingFrame frame = new CodingFrame();

            frame.ClassNumber = classNumber;
            frame.ContentLength = contentLength;
            frame.FrameLength = tagNumberSize + lengthSize + 1;
            frame.PC = pc;
            frame.Tag = new Tag(DecodeTagClass(classNumber), tagNumber);
            frame.TagNumber = tagNumber;

            return frame;
        }

        private TagClass DecodeTagClass(int classNumber)
        {
            switch (classNumber)
            {
                case 0: return TagClass.Universal;
                case 1: return TagClass.Application;
                case 2: return TagClass.ContextSpecific;
                case 3: return TagClass.Private;
                default:
                    throw new Asn1InternalException("Invalid decoding of the TagClass field in codingframe decoder", "", this);
            }
        }

        private ContentLength DecodeLength(byte[] buffer, long offset, out int lengthSize)
        {
            ContentLength contentLength;
            long value;

            if (buffer[offset] == LengthIndefiniteForm)
            {
                lengthSize = 1;
                return ContentLength.Indefinite;
            }
            else if ((buffer[offset] & LengthLongForm) > 0)
            {
                value = DecodeDefiniteLongLength(buffer, offset, out lengthSize);
            }
            else
            {
                lengthSize = 1;
                value = (long)buffer[offset];
            }

            return new ContentLength(value);
        }

        private long DecodeDefiniteLongLength(byte[] buffer, long offset, out int lengthSize)
        {
            int expandSize = buffer[offset] & DefiniteLongLengthMask;
            if (expandSize > MaxDefiniteLongLength)
                throw new EncodingStructureException(buffer, offset,
                    "Current value of the length exceed maximum supported value. " +
                    $"Max supported value is 64 bits (8 bytes) but decoded form consist of {expandSize} bytes");

            long length = 0;
            for (int i = 1; i <= expandSize; i++)
            {
                length <<= 8;
                length |= (long)buffer[offset + i];
            }

            // include 'expand size' byte above
            lengthSize = expandSize + 1;

            return length;
        }

        private long DecodeTagNumber(byte[] buffer, long offset, out int tagNumberLength)
        {
            long tagNumber = buffer[offset] & TagNumberMask;

            if (tagNumber == HighTagNumber)
            {

                tagNumber = DecodeHighTagNumber(buffer, offset, out tagNumberLength);
            }
            else
            {
                tagNumberLength = 0;
            }

            return tagNumber;
        }

        private long DecodeHighTagNumber(byte[] buffer, long offset, out int tagNumberLength)
        {
            // TODO ASN1/X690decodedNode Chkeck if this works (decode hoght tag number)
            // high length consist of 5 bits of the first byte of identifier octet
            int lengthInBits = 5;
            int expandSize = 1;

            while ((buffer[expandSize + offset] & HighTagNumberNotFinalByte) > 0)
            {
                expandSize++;
                // fist bit is ignored
                lengthInBits += 7;

                if (lengthInBits > MaxTagLength)
                    throw new EncodingStructureException(buffer, offset, 
                        "Tag number in the expanded form of the current encoding frame is too large. " + 
                        "Maximum value of supported tag number is 64 bits");
            }

            long length = 0;

            length |= (long)(buffer[offset] << 5);
            for (int i = 1; i <= expandSize; i++)
            {
                length |= ((long)buffer[offset + 1 + expandSize] << (i * 7));
            }

            tagNumberLength = expandSize;
            return length;
        }
    }
}
