using System;

namespace Arctium.Shared
{
    public class RandomGenerator
    {
        public static byte[] GenerateNonZeroNewByteArray(int count)
        {
            Random r = new Random();

            byte[] res = new byte[count];

            r.NextBytes(res);

            for (int i = 0; i < res.Length; i++) if (res[i] == 0) res[i] = 1;

            return res;
        }

        public static void GenerateNonZero(byte[] buffer, int offset, int length)
        {
            Random r = new Random();

            r.NextBytes(new Span<byte>(buffer, offset, length));

            for (int i = offset; i < offset + length; i++) if (buffer[i] == 0) buffer[i] = 1;
        }

        public static void Generate(byte[] buffer, int offset, int length)
        {
            Random r = new Random();

            r.NextBytes(new Span<byte>(buffer, offset, length));
        }
    }
}
