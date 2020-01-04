
using Arctium.Cryptography.HashFunctions.FunctionAlgorithms.Keccak;
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
            //string fileName = @"C:\Users\Marek\Desktop\nauka niekonwencjonalna\VIDEO\BaldTV\POLA MORFICZNE - CZĘŚĆ 2 - TEMATY RUPERTA SHELDRAKE'A.mp4";
            string fileName = @"C:\Users\Marek\Desktop\nauka niekonwencjonalna\VIDEO\BaldTV\OKRĄGŁE LOTNISKO JUŻ WKRÓTCE - PROJEKT ENDLESS RUNWAY.mp4";

            SHA512 mscor = SHA512.Create("SHA512");
            SHA2_512 arc = new SHA2_512();
            Stream file = new FileStream(fileName, FileMode.Open);
            Stopwatch stopwatch = new Stopwatch();

            GC.Collect();
            GC.RemoveMemoryPressure(0x100000);
            GC.WaitForPendingFinalizers();
            GC.TryStartNoGCRegion(0x10000);


           // stopwatch.Start();
           // byte[] mscorResult = mscor.ComputeHash(file);
           // stopwatch.Stop();
           // Console.WriteLine("cor:" + stopwatch.ElapsedMilliseconds/1000);
           // file.Seek(0, SeekOrigin.Begin);
            stopwatch.Start();
            arc.HashBytes(file);
            byte[] arcRes = arc.HashFinal();
            stopwatch.Stop();
            Console.WriteLine("arc: " + stopwatch.ElapsedMilliseconds/1000);



            
        }
    }
}
