using System;
using System.IO;
using System.Text;
using Arctium.Cryptography.HashFunctions;


namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main(string[] args)
        {
            SHA256 sha224 = new SHA256();

            //FileStream s = new FileStream("C:\\Users\\Marek\\Desktop\\feedbooks_book_15.pdf", FileMode.Open);

            string a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            //for (int i = 0; i < 56; i++)
            //{
            //    a += "a";
            //}
            Console.WriteLine(a);
            //sha224.HashBytes(s);c
            sha224.HashBytes(Encoding.ASCII.GetBytes(a)) ;
            byte[] hash = sha224.HashFinal();


            Console.WriteLine();
            for (int i = 0; i < hash.Length; i++)
            {
                Console.Write("{0:X2} ",hash[i]);
            }
        }
    }
}
