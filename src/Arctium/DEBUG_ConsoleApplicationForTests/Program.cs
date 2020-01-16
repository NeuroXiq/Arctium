using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.XOF;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;


namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main(string[] args)
        {
            //var sha3 = new SHA3_384();

            var shake = new SHAKE256();

            //byte[] input = Encoding.ASCII.GetBytes("abcd");
            string feed = "";

            byte[] result = new byte[(1600-512)/8];
            Console.WriteLine(feed);
            Console.WriteLine();
            shake.Feed(Encoding.ASCII.GetBytes(feed));
            shake.FeedEnd();

            for (int i = 0; i < 10; i++)
            {
                shake.GenerateNextOutput(result, 0, 1);
                foreach (byte b in result)
                {
                    Console.Write("{0:X2}", b);
                }
            }
            

        }
    }
}
