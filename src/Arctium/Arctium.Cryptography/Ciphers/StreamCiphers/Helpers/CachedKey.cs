using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.Ciphers.StreamCiphers.Helpers
{
    unsafe class CachedKey
    {
        byte[] key;
        int keyLength;

        int toUtilizeCount;

        public CachedKey(int keyLengthInBytes)
        {
            key = new byte[keyLengthInBytes];
            keyLength = keyLengthInBytes;
            toUtilizeCount = 0;
        }

        public void RefreshKey(byte[] keyStream)
        {
            if (keyStream.Length != keyLength)
                throw new InvalidOperationException("Cannot refresh key because length of the " +
                    "buffer do not match length of the key");

            for (int i = 0; i < keyLength; i++)
            {
                key[i] = keyStream[i];
            }

            toUtilizeCount = keyLength;
        }

        public int UtilizeExitingKeyXor(byte[] input, long inputOffset, long inputLength, byte[] output, long outputOffset)
        {
            if (toUtilizeCount < 1) return 0;

            int count = inputLength > toUtilizeCount ? toUtilizeCount : (int)inputLength;

            for (int i = 0; i < count; i++)
            {
                output[i + outputOffset] = (byte)(input[inputOffset + i] ^ key[keyLength - toUtilizeCount + i]);
            }

            toUtilizeCount -= count;

            return count;
        }
    }
}
