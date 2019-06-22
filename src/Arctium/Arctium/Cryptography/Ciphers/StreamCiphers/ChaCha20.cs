using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Arctium.Cryptography.Ciphers.StreamCiphers
{
    /// <summary>
    /// ChaCha20 Stream cipher
    /// </summary>
    public class ChaCha20
    {
        //default chacha20 constant value. This value is always set in ctor.
        readonly byte[] DefaultChaCha20Constant = new byte[]  { 0x61,0x70,0x78,0x65, 0x33,0x20,0x64,0x6e, 0x79,0x62,0x2d,0x32, 0x6b,0x20,0x65,0x74 };

        //fields used by CreateInitialState() method. Initial state is always created using this public fields.

        private byte[] key;
        private byte[] counter;
        private byte[] nonce;
        private byte[] constant;

        /// <summary>
        /// Key (bytes in big endian format) used to encrypt data
        /// </summary>
        public byte[] Key
        {
            get { return key; }
            set
            {
                if (value.Length == 32)
                    key = value;
                else throw new ArgumentException("Invalid length of the key. Key length must be 256 bits (32 bytes).");
            }
        }

        /// <summary>
        /// Counter parameter indicating transforming block in stream
        /// </summary>
        public byte[] Counter
        {
            get { return counter; }
            set
            {
                if (value.Length == 4) counter = value;
                else throw new ArgumentException("Invalid length of Counter param. Counter length must be 32 bit (4 bytes).");
            }
        }
        /// <summary>
        /// Nonce parameter
        /// </summary>
        public byte[] Nonce
        {
            get { return nonce; }
            set
            {
                if (value.Length == 12) { nonce = value; }
                else throw new ArgumentException("Invalid length of the none param. Nonce length must be 96 bits (12 bytes).");
            }
        }
        /// <summary>
        /// Constant value. In ctor this value is set to default ChaCha20 constant 12 bytes bt can be changed by modifying values in this array before transforming data.
        /// </summary>
        public byte[] Constant
        {
            get { return constant; } 
            set
            {
                if (value.Length == 16) constant = value;
                else throw new ArgumentException("Invalid length of Consntant value. Constan length must be 128 bits (16 bytes)");
            }
        }

        /// <summary>
        /// Creates new instance of <see cref="ChaCha20"/>
        /// All byte array values are passed directly to ChaCha20 'state' ( in big-endian format).
        /// </summary>
        /// <param name="key">Key used to encrypt data. Bytes order in big-endian (most significant byte first)</param>
        /// <param name="counter">Counter parameter indicating encryption block in stream. Bytes treated as big-endian value (most significant byte first)</param>
        /// <param name="nonce">ChaCha20 nonce</param>
        public ChaCha20(byte[] key, byte[] counter, byte[] nonce)
        {
            //parameter validation. Setters throw exception when parameters are invalid
            Key = key;
            Counter = counter;
            Nonce = nonce;
            Constant = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                Constant[i] = DefaultChaCha20Constant[i];
            }
        }

        /// <summary>
        /// Encrypt data buffer
        /// </summary>
        /// <param name="buffer">Buffer contains bytes to encrypt</param>
        /// <param name="offset">Offset where start encryption</param>
        /// <param name="length">Bytes count to encrypt</param>
        /// <param name="outputBuffer">Encryption output buffer</param>
        /// <param name="outputOffset">Position in output buffer where start writing encrypted bytes</param>
        /// <returns></returns>
        public int Encrypt(byte[] buffer, int offset, int length, byte[] outputBuffer, int outputOffset)
        {
            //consider that new state is always created based on public fields (cipher params eg Counter,Nonce).
            
            uint[] state = CreateInitialState();
            
            //counter index is fixed: 
            //this index is used only to increment cointer in state.
            //'state' do not change after GenerateKeyStream method call
            int counterIndexInState = 12;

            byte[] keyStream = new byte[64];


            //
            // first encrypt all 64-bytes chunks
            //

            int chunksCount = length / 64;
            int toEncryptOffset = offset;
            int outOffset = outputOffset;

            for (int i = 0; i < chunksCount; i++)
            {
                GenerateKeyStream(state, keyStream);
                
                for (int j = 0; j < 64; j++)
                {
                    outputBuffer[j + outOffset] = (byte)(keyStream[j] ^ buffer[toEncryptOffset + j]);
                }
                outOffset += 64;
                toEncryptOffset += 64;
                state[counterIndexInState]++;
            }


            //
            // encrypt last no-64 length chunk
            //

            int lastChunkLength = length % 64;
            GenerateKeyStream(state, keyStream);

            for (int i = 0; i < lastChunkLength; i++)
            {
                outputBuffer[i + outOffset] = (byte)(keyStream[i] ^ buffer[toEncryptOffset + i]);
            }

            return length;
        }
        public int Decrypt(byte[] buffer, int offset, int length, byte[] outputBuffer, int outputOffset)
        {
            return Encrypt(buffer, offset, length, outputBuffer, outputOffset);
        }

        public int Encrypt(Stream inputStream, Stream outputStream)
        {
            throw new NotImplementedException();
        }

        public int Decrypt(Stream inputStream, Stream outputStream)
        {
            throw new NotImplementedException();
        }

        uint[] reusableInnerBlockBuffer = new uint[16];
        private void GenerateKeyStream(uint[] currentState, byte[] outputBuffer)
        {
            for (int i = 0; i < 16; i++) reusableInnerBlockBuffer[i] = currentState[i];

            //generate key stream (as uint[] array, not converted to byte array)

            for (int i = 0; i < 10; i++)
            {
                InnerBlock(reusableInnerBlockBuffer);
            }
            
            for (int i = 0; i < 16; i++)
            {
                reusableInnerBlockBuffer[i] += currentState[i];
            }

            //convert to byte array

            //converts every uint to 4 bytes
            int outIndex = 0;
            for (int i = 0; i < 16; i++)
            {
                outputBuffer[outIndex + 0] = (byte)((reusableInnerBlockBuffer[i] & 0x000000FF) >> 0);
                outputBuffer[outIndex + 1] = (byte)((reusableInnerBlockBuffer[i] & 0x0000FF00) >> 8);
                outputBuffer[outIndex + 2] = (byte)((reusableInnerBlockBuffer[i] & 0x00FF0000) >> 16);
                outputBuffer[outIndex + 3] = (byte)((reusableInnerBlockBuffer[i] & 0xFF000000) >> 24);

                outIndex += 4;
            }
        }

        private void InnerBlock(uint[] state)
        {
            Qround(state, 0, 4, 8, 12);
            Qround(state, 1, 5, 9, 13);
            Qround(state, 2, 6, 10, 14);
            Qround(state, 3, 7, 11, 15);
            Qround(state, 0, 5, 10, 15);
            Qround(state, 1, 6, 11, 12);
            Qround(state, 2, 7, 8, 13);
            Qround(state, 3, 4, 9, 14);
        }
        private uint[] CreateInitialState()
        {
            uint[] initialState = new uint[16];

            for (int i = 0; i < 4; i++)
                initialState[i] = ToUInt32(Constant, i * 4);
            for (int i = 0; i < 8; i++)
                initialState[i + 4] = ToUInt32(Key, i * 4);

            initialState[12] = ToUInt32(Counter, 0);

            for (int i = 0; i < 3; i++)
                initialState[i + 13] = ToUInt32(Nonce, i * 4);

            return initialState;
        }
        private void Qround(uint[] state, int aIndex, int bIndex, int cIndex, int dIndex)
        {
            
            state[aIndex] += state[bIndex];
            state[dIndex] ^= state[aIndex];
            state[dIndex] = RotL(state[dIndex], 16);
            
            state[cIndex] += state[dIndex];
            state[bIndex] ^= state[cIndex];
            state[bIndex] = RotL(state[bIndex], 12);
            
            state[aIndex] += state[bIndex];
            state[dIndex] ^= state[aIndex];
            state[dIndex] = RotL(state[dIndex], 8);
            
            state[cIndex] += state[dIndex];
            state[bIndex] ^= state[cIndex];
            state[bIndex] = RotL(state[bIndex], 7);
            
        }

        private uint ToUInt32(byte[] buffer, int offset)
        {
            return (uint)((buffer[offset + 0] <<  24) +
                          (buffer[offset + 1] << 16)  +
                          (buffer[offset + 2] <<  8)  +
                          (buffer[offset + 3] <<  0));
        }

        private uint RotL(uint number, int length)
        {
            return ((number << length) | (number >> (32 - length)));
        }
    }
}
