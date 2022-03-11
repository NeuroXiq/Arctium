using Arctium.Cryptography.HashFunctions.CRC;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Buffers;
using System.IO;

namespace Program
{
    class Program
    {
        static void Main()
        {
            Whirlpool w = new Whirlpool();

            w.HashBytes(b);

            var hash = w.HashFinal();

            MemDump.HexDump(hash);
        }
    }
}
