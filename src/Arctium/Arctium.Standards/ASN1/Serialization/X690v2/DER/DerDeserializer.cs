using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.Serialization.X690v2.Exceptions;
using Arctium.Shared.Helpers.DataStructures;
using System;
using System.Collections;
using System.Collections.Generic;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER
{
    public static class DerDeserializer
    {
        private static readonly DerDeserializerOptions Options = DerDeserializerOptions.Default;


        const byte ClassMask = 0xC0;
        const byte IsConstructedMask = 0x20;
        const byte HighTagNumber = 0x1F;
        const byte LengthIsInLongForm = 0x80;
        const byte LengthLongFormBytesCount = 0x7F;

        public static DerDecoded Deserialize(byte[] buffer, long offset)
        {
            Stack<DerDecoded> constructorsRecursion = new Stack<DerDecoded>();

            long nextTagOffset;
            DerDecoded first = DecodeNext(buffer, offset);

            if (!first.IsConstructed) return first;

            constructorsRecursion.Push(first);
            nextTagOffset = first.ContentOffset;
            long currentConstructorEnd = first.ContentOffset + first.ContentLength;

            while (true)
            {
                if (nextTagOffset >= currentConstructorEnd)
                {
                    if (constructorsRecursion.Count == 1) break;

                    var childConstructor = constructorsRecursion.Pop();
                    var parentConstructor = constructorsRecursion.Peek();
                    parentConstructor.Constructed.Append(childConstructor);

                    currentConstructorEnd = parentConstructor.ContentOffset + parentConstructor.ContentLength;
                    continue;
                }

                DerDecoded decoded = DecodeNext(buffer, nextTagOffset);

                if (decoded.IsConstructed)
                {
                    constructorsRecursion.Push(decoded);
                    nextTagOffset = decoded.ContentOffset;
                    currentConstructorEnd = decoded.ContentOffset + decoded.ContentLength;
                }
                else
                {
                    constructorsRecursion.Peek().Constructed.Append(decoded);
                    nextTagOffset = decoded.ContentOffset + decoded.ContentLength;
                }
            }

            return constructorsRecursion.Pop();
        }

        private static DerDecoded DecodeNext(byte[] buffer, long offset)
        {
            Tag curTag;
            bool isConstructed;
            long contentLength;
            long contentOffset;

            long identifierOctetsLength =
                DecodeIdentifierOctets(
                buffer,
                offset,
                out curTag,
                out isConstructed);

            long lengthBytesOffset = offset + identifierOctetsLength;
            long lengthBytesCount = DecodeContentLength(buffer, lengthBytesOffset, out contentLength);
            contentOffset = lengthBytesOffset + lengthBytesCount;

            long totalLength = lengthBytesCount + contentLength + identifierOctetsLength;

            DerDecoded decodedType = new DerDecoded(curTag, offset, totalLength, isConstructed, contentOffset, contentLength);
            if (isConstructed) decodedType.Constructed = new DArray<DerDecoded>();

            return decodedType;
        }

        private static long DecodeContentLength(byte[] buffer, long offset, out long length)
        {
            if ((buffer[offset] & LengthIsInLongForm) > 0)
            {
                int bytesCount = buffer[offset] & LengthLongFormBytesCount;
                if(bytesCount > 8)
                throw new DerDeserializerException("Content length exceed 32-bit size", buffer, offset);

                ulong resultLength = 0;
                int shift = 0;
                for (long i = offset + bytesCount; i >= offset + 1; i--, shift += 8)
                {
                    resultLength |= ((ulong)buffer[i] << shift);
                }

                length = (long)resultLength;
                return 1 + bytesCount;
            }
            else
            {
                length = buffer[offset];
                return 1;
            }
        }

        private static long DecodeIdentifierOctets(byte[] buffer, long offset, out Tag tag, out bool isConstructed)
        {
            int classNumber = (buffer[offset] & ClassMask) >> 6;
            isConstructed = (buffer[offset] & IsConstructedMask) > 0;
            long tagNumber = -1;

            if ((buffer[offset] & HighTagNumber) == HighTagNumber)
            {
                // TODO ASN1/ X690v2 DER decoder, implement hight tag number
                throw new NotImplementedException("hightagnumber");
            }
            else
            {
                tagNumber = buffer[offset] & HighTagNumber;
            }

            tag = new Tag(GetTagClass(classNumber), tagNumber);

            // ignoring high tag number
            return 1;
        }


        private static TagClass GetTagClass(int classNumber)
        {
            switch (classNumber)
            {
                case 0: return TagClass.Universal;
                case 1: return TagClass.Application;
                case 2: return TagClass.ContextSpecific;
                case 3: return TagClass.Private;
                default: throw new Exception("invalid class number");
            }
        }
    }
}
