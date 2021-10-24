using System;

namespace Arctium.CryptoFunctions
{
    class RandomGenerator
    {
        // classic, unsafe pseudo random generator
        private Random classicRandom;

        public RandomGenerator()
        {
            classicRandom = new Random();
        }

        public void GenerateBytes(byte[] buffer, int offset, int count)
        {
            for (int i = 0; i < count; i++)
            {
                buffer[i + offset] = (byte)classicRandom.Next();
            }
        }

        public void GenerateBytes(byte[] buffer, int count) { GenerateBytes(buffer, 0, count); }
    }
}
