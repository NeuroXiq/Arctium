using Arctium.Cryptography.HashFunctions.Hashes;
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
            var sha3 = new SHA3_512();


            byte[] input = Encoding.ASCII.GetBytes("abcd");

            //Stream input = new FileStream(@"C:\Users\Marek\Desktop\feedbooks_book_15.pdf",FileMode.Open);

            sha3.HashBytes(input);
            byte[] result = sha3.HashFinal();

            foreach (byte b in result)
            {
                Console.Write("{0:X2}", b);
            }

        }
    }
}
