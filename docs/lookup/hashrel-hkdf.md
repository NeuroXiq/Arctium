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
            HMAC hmac = new HMAC(sha, new byte[0], 0, 0);
            HKDF hkdf = new HKDF(hmac);

            byte[] prk = new byte[16];
            byte[] info = new byte[16];
            byte[] output_expand = new byte[32];

            hkdf.Expand(prk, info, output_expand, 32);

            Console.WriteLine("Expand output");
            MemDump.HexDump(output_expand);

            byte[] salt = new byte[16];
            byte[] ikm = new byte[16];
            byte[] extract_output = new byte[32];

            hkdf.Extract(salt, ikm, extract_output);
            Console.WriteLine("Extract output");
            MemDump.HexDump(extract_output);
        }
    }
}

/*
Expand output
3D0B643A 05DC66D4 BAACB456 C2966C2A
4E4F6897 89FADF64 C3D203B4 AF3E3714

Extract output
853C7403 937D8B62 39569B18 4EB7993F
C5F751AE FCEA28F2 C863858E 2D29C50B

 */
```