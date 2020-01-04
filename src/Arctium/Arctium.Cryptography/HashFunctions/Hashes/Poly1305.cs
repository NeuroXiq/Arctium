using System;
using System.IO;
using System.Numerics;

namespace  Arctium.Cryptography.HashFunctions.Hashes
{
    /// <summary>
    /// Poly1305 Hash function created by D. J. Bernstein. ([RFC 8439])
    /// </summary>
    public class Poly1305
    {
        /// <summary>
        /// R part of private key defined in Poly1305.
        /// </summary>
        public byte[] R
        {
            get
            {
                return r;
            }
            set
            {
                if (value.Length == 16) r = value;
                else throw new InvalidOperationException("Invalid length of the R param. Param length must have 16 bytes");
            }
        }

        private byte[] r;

        /// <summary>
        /// S part of private key defined in Poly1305.
        /// </summary>
        public byte[] S
        {
            get { return s; }
            set
            {
                if (value.Length == 16) s = value;
                else throw new InvalidOperationException("Invalid length of the S param. Param length must have 16 bytes");
            }
        }

        private byte[] s;

        /// <summary>
        /// P prime value defined in Poly1305.
        /// </summary>
        public byte[] P
        {
            get { return p; }
            set
            {
                if (value.Length == 17) p = value;
                else throw new ArgumentException("Invalid length of P param. P length must have 17 bytes");
            }
        }

        private byte[] p;

        /// <summary>
        /// One time key used to derivate <see cref="Poly1305.S"/> and <see cref="Poly1305.P"/>
        /// </summary>
        public byte[] OneTimeKey
        {
            get { return oneTimeKey; }
            set
            {
                if (value.Length == 32) oneTimeKey = value;
                else throw new ArgumentException("Invalid length of one time key. One time key length must have 256 bits (32 bytes).");
            }
        }

        private byte[] oneTimeKey;

        // P prime defined in Poly1305 sepcification. This field is constant and must not be changed
        // this number is represended in little-endian format 
        private static readonly BigInteger pPrime = new BigInteger(new byte[] { 0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x03 });

        //
        // all private values 
        //

        private BigInteger accumulator;

        private BigInteger clampRBigInt;

        private BigInteger sBigInt;

        private BigInteger pBigInt;

        private byte[] chunksBuffer;

        private int currentChunkLength;

        public Poly1305(byte[] oneTimeKey)
        {
            ResetState(oneTimeKey);
        }

        /// <summary>
        /// Returns current value of computed hash
        /// </summary>
        /// <returns></returns>
        public byte[] GetHash() { return GetCurrentHashFromAccumulator(); }

        /// <summary>
        /// Reset state to inital values using new one time key
        /// </summary>
        public void ResetState(byte[] oneTimeKey)
        {
            P = pPrime.ToByteArray();

            OneTimeKey = oneTimeKey;
            byte[] rValue = new byte[16];
            byte[] sValue = new byte[16];

            for (int i = 0; i < 16; i++)
            {
                rValue[i] = oneTimeKey[i];
                sValue[i] = oneTimeKey[i + 16];
            }
            R = rValue;
            S = sValue;

            currentChunkLength = 0;
            chunksBuffer = new byte[18];

            InitializeBigIntegers();
        }

        /// <summary>
        /// Reset state to inital values using one time key provided in ctor
        /// </summary>
        public void ResetState()
        {
            ResetState(OneTimeKey);
        }

        /// <summary>
        /// Compute hash value from specified data in byte array
        /// </summary>
        /// <param name="buffer">Buffer containing data to hash</param>
        /// <param name="offset">Offset of data</param>
        /// <param name="length">Length of data</param>
        /// <returns>Computed data hash</returns>
        public byte[] ComputeHash(byte[] buffer, int offset, int length)
        {
            TransformNextChunk(buffer, offset, length);
            byte[] hash = TransformLastChunk(new byte[0], 0, 0);

            ResetState();

            return hash;
        }

        /// <summary>
        /// Compute hash value from data stream
        /// </summary>
        /// <param name="stream">Data stream</param>
        /// <returns></returns>
        public byte[] ComputeHash(Stream stream)
        {
            int readed = 0;
            int bufferSize = 0x100;
            byte[] transformBuffer = new byte[18];
            byte[] streamBuffer = new byte[bufferSize];

            while (stream.Read(streamBuffer, readed, bufferSize - readed) > 0)
            {
                if (readed > 16)
                {
                    TransformNextChunk(streamBuffer, 0, readed);
                    readed = 0;
                }
            }

            TransformLastChunk(streamBuffer, 0, readed);

            byte[] hash = GetCurrentHashFromAccumulator();

            ResetState();

            return hash;
        }

        /// <summary>
        /// Transform data in chunked mode, changes internal state
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        public void TransformNextChunk(byte[] buffer, int offset, int length)
        {
            int toCopyLength = length;
            int copied = 0;

            while (toCopyLength > 0)
            {
                int appendLength = 16 - currentChunkLength;

                if (appendLength > toCopyLength)
                {
                    appendLength = toCopyLength;
                }

                Buffer.BlockCopy(buffer, offset + copied, chunksBuffer, currentChunkLength, appendLength);
                currentChunkLength += appendLength;
                copied += appendLength;
                toCopyLength -= appendLength;

                if (currentChunkLength == 16)
                {
                    TransformBlock(chunksBuffer, 16);
                    currentChunkLength = 0;
                }
            }
        }

        /// <summary>
        /// Transform last block of data in chunked mode.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public byte[] TransformLastChunk(byte[] buffer, int offset, int length)
        {
            TransformNextChunk(buffer, offset, length);

            //any bytes need last transform (not transformed in method call above ?)
            if (currentChunkLength > 0)
            {
                TransformBlock(chunksBuffer, currentChunkLength);
            }

            byte[] result = GetCurrentHashFromAccumulator();
            ResetState();

            return result;
        }
        private void ClampR(byte[] sourceR)
        {
            sourceR[3] &= 15;
            sourceR[7] &= 15;
            sourceR[11] &= 15;
            sourceR[15] &= 15;
            sourceR[4] &= 252;
            sourceR[8] &= 252;
            sourceR[12] &= 252;
        }

        private byte[] GetCurrentHashFromAccumulator()
        {
            BigInteger resultNumber = sBigInt + accumulator;

            byte[] resultNumberBytes = resultNumber.ToByteArray();

            //hash is 16 least significant bits
            byte[] hashValue = new byte[16];

            Buffer.BlockCopy(resultNumberBytes, 0, hashValue, 0, 16);

            return hashValue;
        }

        private void InitializeBigIntegers()
        {
            byte[] rCpy = new byte[17];
            byte[] sCpy = new byte[17];
            byte[] pCpy = new byte[18];

            for (int i = 0; i < 16; i++)
            {
                rCpy[i] = R[i];
                sCpy[i] = S[i];
                pCpy[i] = P[i];
            }

            pCpy[16] = P[16];
            ClampR(rCpy);

            accumulator = new BigInteger();
            clampRBigInt = new BigInteger(rCpy);
            sBigInt = new BigInteger(sCpy);
            pBigInt = new BigInteger(pCpy);
        }

        private int Transform16BytesChunks(byte[] buffer, int offset, int length)
        {
            int transformedBytes = 0;
            byte[] blockToTransform = new byte[18];
            while (transformedBytes + 16 <= length)
            {
                Buffer.BlockCopy(buffer, transformedBytes + offset, blockToTransform, 0, 16);
                blockToTransform[16] = 0;
                transformedBytes += 16;
                TransformBlock(blockToTransform, 16);
            }

            return transformedBytes;
        }

        // takes 18-bytes length array with data of 'dataLength' and 
        // process hash transform. Assumes that block have exactly 18 bytes.
        // for performance reasons, fixed length transform buffer can be allocated only once
        // with no future need to reallocate new buffer to process new chunk. (see Transform16BytesChunks()) 
        private void TransformBlock(byte[] blockToTransform, int dataLength)
        {
            if (blockToTransform.Length != 18) throw new Exception("INTERNAL :: Block length must have 18 bytes length (fixed size), wher first 0-17 byte are data bytes");

            //clear upper bytes 
            for (int i = dataLength; i < 18; i++)
            {
                blockToTransform[i] = 0;
            }

            //set 1 bit beyond
            blockToTransform[dataLength] = 1;

            //ctor takes array in little-endian format, all is fine (no need to reverse)
            BigInteger accumulatorAddition = new BigInteger(blockToTransform);

            accumulator = ((accumulator + accumulatorAddition) * clampRBigInt) % pBigInt;
        }
    }
}
