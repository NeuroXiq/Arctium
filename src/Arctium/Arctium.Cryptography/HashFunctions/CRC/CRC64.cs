using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Interfaces;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.CRC
{
    public class CRC64 : IProcessBytes
    {
        /// <summary>
        /// Plynomial used in CRC calculations
        /// </summary>
        public readonly ulong Polynomial;

        /// <summary>
        /// Indicates if all bits in input bytes are reversed. E.g
        /// if this value is true then following byte: 01000011 is reversed into 11000010 and then processed
        /// </summary>
        public readonly bool InputReflected;

        /// <summary>
        /// Indicates if all bits in result uint are reversed. Similar like InputReflected but 32 bit value is reversed/>
        /// </summary>
        public readonly bool ResultReflected;

        /// <summary>
        /// Initial value for 
        /// </summary>
        public readonly ulong InitialValue;

        /// <summary>
        /// Result will be xored with FinalXorValue right before return it
        /// </summary>
        public readonly ulong FinalXorValue;

        private ulong result;
        private ulong[] lookupTable;

        public CRC64(ulong polynomial,
            bool inputReflected,
            bool resultReflected,
            ulong initialValue,
            ulong finalXorValue)
        {
            Polynomial = polynomial;
            InputReflected = inputReflected;
            ResultReflected = resultReflected;
            FinalXorValue = finalXorValue;
            InitialValue = initialValue;
            SetLookupTable();
        }

        private void SetLookupTable()
        {
            lookupTable = new ulong[256];

            for (int i = 0; i < 256; i++)
            {
                ulong result = 0;
                ulong value = (ulong)i << 55;
                ulong msbit = (ulong)((ulong)1 << 63);
                
                for (int j = 0; j < 8; j++)
                {
                    value <<= 1;

                    if ((value & msbit) != 0)
                    {
                        result ^= (Polynomial << (7 - j));
                        value = (value) ^ (Polynomial >> 1);
                    }
                }

                lookupTable[i] = result;
            }
        }

        public void Process(byte[] bytes)
        {
            Process(bytes, 0, bytes.Length);
        }

        public void Process(byte[] bytes, long offset, long length)
        {
            for (long i = offset; i < length + offset; i++)
            {
                ProcessByte(bytes[i]);
            }
        }

        public void Process(Stream stream)
        {
            SimpleBufferForStream simpleBuffer = new SimpleBufferForStream();

            simpleBuffer.MediateAllBytesInto(stream, this);
        }

        public ulong Result()
        {
            ulong resultAfterXor = result ^ FinalXorValue;
            ulong final = ResultReflected ? BinOps.BitReflect(resultAfterXor) : resultAfterXor;

            return final;
        }

        public void Reset()
        {
            result = 0;
        }

        private void ProcessByte(byte b)
        {
            b = InputReflected ? BinOps.BitReflect(b) : b;

            int idx = (int)((((ulong)b << 56) ^ result) >> 56);

            ulong v = lookupTable[idx];

            result = (result << 8) ^ v;
        }
    }
}
