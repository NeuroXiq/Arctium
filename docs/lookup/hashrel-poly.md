```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 *
 * 
 */


using Arctium.Cryptography.Ciphers.DiffieHellman;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.KDF;
using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.DiffieHellman;
using Arctium.Standards.EllipticCurves;
using Arctium.Standards.FileFormat.PEM;

namespace ConsoleAppTest
{
    internal class MainProgram
    {
        static void Main()
        {
            byte[] key = new byte[32];
            key[0] = key[12] = key[25] = 5;
            Poly1305 poly = new Poly1305(key);

            byte[] textToHmac = new byte[256];
            textToHmac[0] = textToHmac[5] = textToHmac[128] = 5;
            

            poly.Process(textToHmac, 0, textToHmac.Length);
            byte[] result = poly.Final();

            Console.WriteLine("Result");
            MemDump.HexDump(result);
        }
    }
}

/*
Result
B5AF4992 EBA64E8D 14AEAE30 9586A433


 */
```