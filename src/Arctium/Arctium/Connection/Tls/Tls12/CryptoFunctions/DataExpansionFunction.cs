using System;
using System.Security.Cryptography;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

namespace Arctium.Standards.Connection.Tls.Tls12.CryptoFunctions
{
    class DataExpansionFunction
    {
        HashAlgorithmType macAlgo;

        public DataExpansionFunction(HashAlgorithmType macAlgo)
        {
            this.macAlgo = macAlgo;
        }

        ///<summary></summary>
        ///<param name="length">Length of the output array in bytes</param>
        ///<remarks></remarks>
        public byte[] Generate(byte[] secret, byte[] seed, int length)
        {
            HMAC hmac = BuildHmac(secret);
            

            int hashSizeInBytes = hmac.HashSize / 8;
            int hashesCount = ((length - 1) / hashSizeInBytes) + 1;
            int nextWriteOffset = 0;
            byte[] hashesSequence = new byte[hashesCount * hashSizeInBytes];


            byte[] a = seed;
            a = hmac.ComputeHash(a); // a(1)

            for (int i = 0; i < hashesCount; i++)
            {
                byte[] b = hmac.ComputeHash(Join(a, seed));
                a = hmac.ComputeHash(a);
                
                Array.Copy(b, 0, hashesSequence, nextWriteOffset, hashSizeInBytes);

                nextWriteOffset += hashSizeInBytes;
            }


            //trim start to 'length' param
            byte[] result = new byte[length];
            Array.Copy(hashesSequence, 0, result, 0, length);

            return result;
        }

        private HMAC BuildHmac(byte[] secret)
        {
            switch (macAlgo)
            {
                case HashAlgorithmType.MD5: return new HMACMD5(secret);
                case HashAlgorithmType.SHA1: return new HMACSHA1(secret);
                case HashAlgorithmType.SHA256: return new HMACSHA256(secret);
                case HashAlgorithmType.SHA384: return new HMACSHA384(secret);
                case HashAlgorithmType.SHA512: return new HMACSHA512(secret);
                default: throw new InvalidOperationException("not implemented hmac ??");
            }
        }

        private byte[] Join(byte[] current, byte[] seed)
        {
            byte[] joined = new byte[current.Length + seed.Length];

            Array.Copy(current, 0, joined, 0, current.Length);
            Array.Copy(seed, 0, joined, current.Length, seed.Length);

            return joined;
        }
    }
}
