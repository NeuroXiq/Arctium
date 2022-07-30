using Arctium.Shared.Helpers.Buffers;
using System;

namespace Arctium.Shared.Security
{
    public class DefaultUnsafePRNG : RandomGenerator
    {
        private Random random;

        public DefaultUnsafePRNG()
        {
            this.random = new Random();
        }

        public override void Generate(byte[] buffer, long offset, long length)
        {
            byte[] temp = new byte[length];
            random.NextBytes(temp);

            MemCpy.Copy(temp, 0, buffer, offset, length);
        }
    }
}
