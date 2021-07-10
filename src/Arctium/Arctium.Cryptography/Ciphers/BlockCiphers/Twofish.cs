using System;
using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Cryptography.Ciphers.BlockCiphers.Shared;
using Arctium.Cryptography.Ciphers.Helpers;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    /*
     * This is a class which execute methods from TwofishEncryption static class
     * This class holds cipher state after Twofish key schedule and implements 
     * cipher mode of operation
     * 
     * Encryption algorithms use unsafe context - pointers, stackallocks etc. and all 
     * encryptio functions of the Twofish cipher are located in TwofishEncryption static class.
     * This class is just a wrapper, where state of the cipher can be preserved between iterations 
     * from one block to block and also implements Cipher Block Modes (ECB CBC etc.). 
     * This is a intermediate environment between managed and unmanaged environment for Twofish cipher.
     * 
     */


    /// <summary>
    /// Represents symmetric block cipher.
    /// </summary>
    public unsafe class Twofish : BlockCipher
    {
        const int InputBlockLengthInBits = 128;

        // this three fileds are cipher state after key schedule
        private int[] validKeyLengths = new int[] { 128, 192, 256 };
        private byte[] expandedKey;
        //third key vector
        private byte[] sKeyVector;

        /// <summary>
        /// Creates new instance of the Twofish cipher. 
        /// </summary>
        /// <param name="key">Secret bytes</param>
        public Twofish(byte[] key, BlockCipherMode mode) : base(key,null, InputBlockLengthInBits, mode)
        {
            CiphersValidation.ThrowIfInvalidKeyLength(nameof(Twofish), validKeyLengths, key.Length * 8);

            Initialize();
        }

        public override long Decrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            CryptoTransform(input, offset, output, outputOffset, length, false);

            return length;
        }

       

        public override long Encrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            CryptoTransform(input, offset, output, outputOffset, length, true);

            return length;
        }

        /// <summary>
        /// isEncryption - if true encrypt data if false decrypt
        /// </summary>
        private void CryptoTransform(byte[] input, long offset, byte[] output, long outputOffset, long length,
            bool isEncryption)
        {
            // Prepare unsafe environment for crypto transforms
            // Cipher must me initialized before this method call

            if (length == 0) return;
            CiphersValidation.ThrowIfBlockLengthNotDivisible("Twofish", length, 128);

            // Make current state unsafe
            fixed (byte* inputPtr = &input[0], outputPtr = &output[0],
                expandedKeyPtr = &expandedKey[0], skeyVectorPtr = &sKeyVector[0])
            {
                // Twofish parameters ('cipher state')
                TwofishAlgorithm.TwofishParms parameters = new TwofishAlgorithm.TwofishParms();
                parameters.Input = inputPtr;
                parameters.Output = outputPtr;
                parameters.KeyLength = key.Length * 8;
                parameters.ExpandedKey = (uint*)expandedKeyPtr;
                parameters.SKeyVector = (uint*)skeyVectorPtr;

                long blocksCount = length / 16;

                // switch to encryption mode ECB, CBC etc.
                if (isEncryption)
                {
                    EncryptionSwitchBasedOnMode(parameters, blocksCount);
                }
                else
                {
                    DecryptionSwitchBasedOnMode(parameters, blocksCount);
                }
            }
        }

        private void EncryptionSwitchBasedOnMode(TwofishAlgorithm.TwofishParms parameters, long blocksCount)
        {
            switch (BlockCipherMode)
            {
                case BlockCipherMode.ECB: EncryptECB(parameters, blocksCount); break;
                default:
                    throw new NotSupportedException("Twofish not suppotted for " + BlockCipherMode.ToString());
            }
        }

        private void DecryptionSwitchBasedOnMode(TwofishAlgorithm.TwofishParms parameters, long blocksCount)
        {
            switch (BlockCipherMode)
            {
                case BlockCipherMode.ECB: DecryptECB(parameters, blocksCount); break;
                default:
                    throw new NotSupportedException("Twofish not suppotted for " + BlockCipherMode.ToString());
            }
        }


        private void Initialize()
        {
            // Generate scheduled key + third key vector (skeyvector)
            int keyLengthInQWords = key.Length / 8;
            int keyLengthInBits = key.Length * 8;
            expandedKey = new byte[40 * 4]; // 40 uints
            sKeyVector = new byte[keyLengthInQWords * 8]; // 2 ulongs

            fixed (byte* expandedKeyPtr = &expandedKey[0], sKeyVectorPtr = &sKeyVector[0], inputKeyPtr = &key[0])
            {
                TwofishAlgorithm.KeySchedule(inputKeyPtr, (uint*)expandedKeyPtr, (uint*)sKeyVectorPtr, keyLengthInBits);
            }
        }

        // Cipher block modes

        // Encrypt

        private void EncryptECB(TwofishAlgorithm.TwofishParms parameters, long blocksCount)
        {
            for (int i = 0; i < blocksCount; i++)
            {
                TwofishAlgorithm.EncryptBlock(parameters);
                parameters.Input += 16;
                parameters.Output += 16;
            }
        }

        // Decrypt

        private void DecryptECB(TwofishAlgorithm.TwofishParms parameters, long blocksCount)
        {
            for (int i = 0; i < blocksCount; i++)
            {
                TwofishAlgorithm.DecryptBlock(parameters);
                parameters.Input += 16;
                parameters.Output += 16;
            }
        }
    }
}
