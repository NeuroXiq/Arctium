using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.Utils
{
    public class RandomGenerator
    {
        public static byte[] GenerateNewByteArray(int count)
        {
            Random r = new Random();

            byte[] res = new byte[count];

            r.NextBytes(res);

            return res;
        }
    }
}
