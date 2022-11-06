```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 *
 * 
 */


using Arctium.Cryptography.Ciphers.DiffieHellman;
using Arctium.Cryptography.HashFunctions.Hashes;
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
            // Creating hash function and using is easy
            // find hash function by name, create instance
            // and hash bytes

            Whirlpool whirlpool = new Whirlpool();
            BLAKE3 blake3 = new BLAKE3();
            SHA3_256 sha3 = new SHA3_256();
            Skein_512 skein = new Skein_512();
            SHA2_256 sha2 = new SHA2_256();
            JH_256 jh256 = new JH_256();
            Streebog_256 streebog256 = new Streebog_256();

            HashSomeBytes(whirlpool);
            HashSomeBytes(blake3);
            HashSomeBytes(sha3);
            HashSomeBytes(skein);
            HashSomeBytes(sha2);
            HashSomeBytes(jh256);
            HashSomeBytes(streebog256);

        }

        static void HashSomeBytes(HashFunction hashFunc)
        {
            byte[] someBytes = new byte[] { 1, 2, 3, 4 };

            hashFunc.HashBytes(someBytes);
            hashFunc.HashBytes(someBytes);
            hashFunc.HashBytes(someBytes);
            hashFunc.HashBytes(someBytes);
            hashFunc.HashBytes(someBytes);

            byte[] computedHash = hashFunc.HashFinal();

            Console.WriteLine("Hash name: {0}", hashFunc.GetType().Name);
            Console.WriteLine("Computed hash: ");
            MemDump.HexDump(computedHash);
        }
    }
}

/*
 Hash name: Whirlpool
Computed hash:
85F235CF A4EB019D 1FA93644 240DC4C5
17284993 B87878A9 9B91A8C5 82ED762F
EA5B803D 13C24F30 73A5C6C7 7BF883D1
B9A2EAF1 FF0017F3 614F6069 7C1A7542

Hash name: BLAKE3
Computed hash:
0CC0BCEC A8333720 06C56727 A169DFC0
C342396D 213E777D C6002299 E2603C9F

Hash name: SHA3_256
Computed hash:
10DD3968 E2C12FA7 02984226 C3BE48B5
A16AEA0A 88AA2FB7 2014F6E3 B745CD04

Hash name: Skein_512
Computed hash:
AA05F7C0 E3167BD1 7EAEC64D 401B5072
48394C3F 809E0B6B 5E9B4882 0CAF61F8
47B6ADB0 00095973 8BE73686 18E22848
2541BF73 7DB06C7A 7EF834DA 8375DD03

Hash name: SHA2_256
Computed hash:
87C65306 CEED6D23 A2A1BF1A 240C549C
ADF0E14F 03D35F14 6A29BB79 E8CD3B24

Hash name: JH_256
Computed hash:
6EBD76FA A58BA4BC 06377018 0883426D
C0C4E018 81EBEBAE AA22C9C0 FDDCCE79

Hash name: Streebog_256
Computed hash:
A46EF46B D434BA43 AC91599D 6A45BCFE
8B99FFA3 D24F83DA BD34A74D 5F78B97D
 */
```