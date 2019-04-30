using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.Crypto
{
    class DataExpansionFunction
    {
        MACAlgorithm macAlgo;

        public DataExpansionFunction() : base()
        {
        }

        public DataExpansionFunction(MACAlgorithm macAlgo)
        {        
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
            else if (macAlgo == MACAlgorithm.SHA)
            {
                hmac = new HMACSHA1(secret);
            }
            else throw new NotSupportedException();

            byte[] result = new byte[length];
            int writed = 0;
            byte[] current = hmac.ComputeHash(Join(seed,seed));

            if (current.Length > length)
            {
                Array.Copy(current, 0, result, 0, length);
                writed = length;
            }
            else
            {
                Array.Copy(current, 0, result, 0, current.Length);
                writed += current.Length;
            }
            

            while (writed < length)
            {
                byte[] nextHash = hmac.ComputeHash(Join(current,seed));
                if (writed + nextHash.Length <= length)
                {
                    Array.Copy(nextHash, 0, result, writed, nextHash.Length);
                    writed += nextHash.Length;
                }
                else
                {
                    // last copy
                    int lastCpyCount = length - writed;
                    Array.Copy(nextHash, 0, result, writed, lastCpyCount);
                    writed += lastCpyCount;
                    break;
                }

                current = nextHash;
            }

    


            return result;
        }

        internal byte[] Generate(byte[] s1, byte[] v)
        {
            throw new NotImplementedException();
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
