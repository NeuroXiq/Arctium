```cs
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Buffers;
using System.Text;

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main()
        {
            // create new instance
            BLAKE2b_512 blake2b = new BLAKE2b_512();

            // input bytes 
            byte[] inputBytes = Encoding.ASCII.GetBytes("abc");

            // hash bytes
            blake2b.HashBytes(inputBytes);

            //blake2b.HashBytes(inputBytes2);
            //blake2b.HashBytes(inputBytes3);
            //blake2b.HashBytes(inputBytes4);
            // ... this method can be called several times as needed
            // typically when working with chunked data

            // compute hash -> no more data
            byte[] blake2bHash = blake2b.HashFinal();

            // show hash to console
            MemDump.HexDump(blake2bHash);

            // [CONSOLE OUTPUT]: 
            // 
            // BA80A53F 981C4D0D 6A2797B6 9F12F6E9
            // 4C212F14 685AC4B7 4B12BB6F DBFFA2D1
            // 7D87C539 2AAB792D C252D5DE 4533CC95
            // 18D38AA8 DBF1925A B92386ED D4009923
        }
    }
}
```