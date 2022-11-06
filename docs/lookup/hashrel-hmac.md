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
            SHA2_256 sha = new SHA2_256();
            byte[] hmacKey = new byte[16];
            HMAC hmac = new HMAC(sha, hmacKey, 0, hmacKey.Length);

            byte[] textToHmac = new byte[256];
            byte[] result = new byte[32];

            hmac.ProcessBytes(textToHmac, 0, 256);
            hmac.Final(result, 0);

            Console.WriteLine("Result");
            MemDump.HexDump(result);
        }
    }
}

/*
Result
1C76C43C DA8BF8D4 6DB15F12 1876CA22
86656194 A6F5EBA5 237ECC34 2C9582AA

 */
```