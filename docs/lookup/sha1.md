```cs
using System;
using System.Text;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Buffers;

/*
 * SHA1 implementation
 * */


namespace Program
{
    class Program
    {
        static void Main()
        {
            Console.WriteLine("SHA1 Example");

            SHA1 sha1 = new SHA1();
            sha1.HashBytes(Encoding.ASCII.GetBytes("Bytes to hash"));
            sha1.HashBytes(Encoding.ASCII.GetBytes("Bytes to hash / chunk 2"));
            sha1.HashBytes(Encoding.ASCII.GetBytes("Bytes to hash / chunk 3"));

            // also can inclue:
            // Stream someStream = ... stream
            // sha1.HashBytes(someStream)
        
            byte[] hash = sha1.HashFinal();

            Console.WriteLine("Computed Hash: ");
            MemDump.HexDump(hash);
            
            /*
             * [Console output]
             *
             * SHA1 Example
             * Computed Hash:
             * 9C552718 90D89A89 441CDD52 5EB8050E
             * 61D70BE5
             *
             * * * * * * */

        }
    }
}
```
