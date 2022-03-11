using Arctium.Cryptography.HashFunctions.CRC;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Shared.Helpers.Buffers;
using System.IO;

namespace Program
{
    class Program
    {
        static void Main()
        {
            //WhirlpoolAlgorithm.Generate();

             var b = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

            //var b = new byte[1024 * 1024 * 1024];

            Whirlpool w = new Whirlpool();

            w.HashBytes(b);

            var hash = w.HashFinal();

            MemDump.HexDump(hash);
        }
    }
}
