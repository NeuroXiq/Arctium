using Arctium.Cryptography.HashFunctions.CRC;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Buffers;

namespace Program
{
    class Program
    {
        static void Main()
        {
            Whirlpool w = new Whirlpool();

            w.HashBytes(new byte[] { (byte)'a', (byte)'b', (byte)'c' });

            var hash = w.HashFinal();

            MemDump.HexDump(hash);
        }
    }
}
