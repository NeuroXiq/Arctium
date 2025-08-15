using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Cryptography.HashFunctions.KDF
{
    /// <summary>
    /// RFC 5869
    /// </summary>
    public class HKDF
    {
        private HMAC hmac;

        public HKDF(HMAC hmac)
        {
            this.hmac = hmac;
        }

        
        /// <summary>
        /// Wrapper for method method with same name (ignoring offsets and lengths)
        /// </summary>
        /// <param name="salt"></param>
        /// <param name="ikm"></param>
        /// <param name="output"></param>
        public void Extract(byte[] salt, byte[] ikm, byte[] output)
        {
            Extract(salt, 0, salt.Length, ikm, 0, ikm.Length, output, 0);
        }

        /// <summary>
        /// HKDF extract function (as rfc specifies)
        /// </summary>
        /// <param name="salt"></param>
        /// <param name="saltOffset"></param>
        /// <param name="saltLength"></param>
        /// <param name="ikm"></param>
        /// <param name="ikmOffset"></param>
        /// <param name="ikmLength"></param>
        /// <param name="output"></param>
        /// <param name="outputOffset"></param>
        public void Extract(
            byte[] salt,
            long saltOffset,
            long saltLength,
            byte[] ikm,
            long ikmOffset,
            long ikmLength,
            byte[] output,
            long outputOffset)
        {
            hmac.ChangeKey(salt, saltOffset, saltLength);

            hmac.ProcessBytes(ikm, ikmOffset, ikmLength);
            hmac.Final(output, outputOffset);
        }

        public void Expand(byte[] prk, byte[] info, byte[] output, long length)
        {
            Expand(prk, 0, prk.Length, info, 0, info.Length, output, 0, length);
        }

        /// <summary>
        /// HKDF-Expand(PRK, info, L) -> OKM
        /// </summary>
        /// <param name="prk">a pseudorandom key of at least HashLen octets (usually, the output from the extract step).
        /// This value is argument for HMAC as 'key' parameter
        /// </param>
        /// <param name="prkOffset"></param>
        /// <param name="prkLength"></param>
        /// <param name="info">Optional context and application specific information (can be a zero-length string)
        /// </param>
        /// <param name="infoOffset"></param>
        /// <param name="infoLength"></param>
        /// <param name="output">Buffer to store output bytes</param>
        /// <param name="outputLength">length of output keying material in octets (<= 255*HashLen)</param>
        public void Expand(byte[] prk,
            long prkOffset,
            long prkLength,
            byte[] info,
            long infoOffset,
            long infoLength,
            byte[] output,
            long outputOffset,
            long outputLength)
        {
            if (outputLength < 1) return;

            long blocksCount = (outputLength + (hmac.HashFunctionHashSizeBytes - 1)) / hmac.HashFunctionHashSizeBytes;

            if (((ulong)blocksCount & 0xFFFFFFFF00000000) != 0) throw new Exception("Not supported output length");

            byte[] counter = new byte[4];
            byte[] prevHmac = new byte[hmac.HashFunctionHashSizeBytes];

            // T1
            hmac.ChangeKey(prk, prkOffset, prkLength);
            counter[3] = 0x01;
            hmac.ProcessBytes(info, infoOffset, infoLength);
            hmac.ProcessBytes(counter, 3, 1);
            hmac.Final(prevHmac, 0);

            long copyLen = outputLength <= hmac.HashFunctionHashSizeBytes ? outputLength : hmac.HashFunctionHashSizeBytes;

            MemCpy.Copy(prevHmac, 0, output, outputOffset, copyLen);

            // T1 written,
            // T2 ... T_n (to output length)
            for (int i = 2; i <= blocksCount; i++)
            {
                // hmac.ChangeKey(prk, prkOffset, prkLength);
                hmac.ProcessBytes(prevHmac);
                hmac.ProcessBytes(info, infoOffset, infoLength);

                MemMap.ToBytes1UIntBE((uint)i, counter, 0);

                int c = -1;

                // minimum amount of bytes to store 'i' as bytes 
                if ((i & 0xFF000000) != 0) c = 4;
                else if ((i & 0x00FF0000) != 0) c = 3;
                else if ((i & 0x0000FF00) != 0) c = 2;
                else c = 1;

                hmac.ProcessBytes(counter, 4 - c, c);
                hmac.Final(prevHmac, 0);

                long alreadyWrittenBytes = ((i - 1) * prevHmac.Length);
                long outputWriteOffset = outputOffset + alreadyWrittenBytes;
                copyLen = prevHmac.Length;

                if (outputWriteOffset + copyLen > outputOffset + outputLength)
                {
                    copyLen = outputLength - alreadyWrittenBytes;
                }

                MemCpy.Copy(prevHmac, 0, output, outputWriteOffset, copyLen);
            }
        }
    }
}
