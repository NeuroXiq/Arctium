﻿using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.CryptoFunctions
{
    class DataExpansionFunction
    {
        MACAlgorithm macAlgo;

        public DataExpansionFunction(MACAlgorithm macAlgo)
        {
            this.macAlgo = macAlgo;
        }

        ///<summary></summary>
        ///<param name="length">Length of the output array in bytes</param>
        ///<remarks></remarks>
        public byte[] Generate(byte[] secret, byte[] seed, int length)
        {
            HMAC hmac;
            if (macAlgo == MACAlgorithm.MD5)
            {
                hmac = new HMACMD5(secret);
            }
            else if (macAlgo == MACAlgorithm.SHA1)
            {
                hmac = new HMACSHA1(secret);
            }
            else throw new NotSupportedException();

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

        private byte[] Join(byte[] current, byte[] seed)
        {
            byte[] joined = new byte[current.Length + seed.Length];

            Array.Copy(current, 0, joined, 0, current.Length);
            Array.Copy(seed, 0, joined, current.Length, seed.Length);

            return joined;
        }
    }
}
