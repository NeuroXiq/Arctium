```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 *
 * 
 */


using Arctium.Cryptography.Ciphers.DiffieHellman;
using Arctium.Cryptography.HashFunctions.CRC;
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
            PredefinedCRC.CRC32_AIXM();

            ComputeSomeCRC(PredefinedCRC.CRC32_AIXM());
            ComputeSomeCRC(PredefinedCRC.CRC32_BASE91_D());
            ComputeSomeCRC(PredefinedCRC.CRC32_BZIP2());
            ComputeSomeCRC(PredefinedCRC.CRC32_ISCSI());
            ComputeSomeCRC(PredefinedCRC.CRC64_GO_ISO());
            ComputeSomeCRC(PredefinedCRC.CRC64_ECMA182());
        }

        private static void ComputeSomeCRC(CRC64 cRC64)
        {
            byte[] bytes = new byte[128];
            bytes[1] = bytes[123] = bytes[4] = 5;
            cRC64.Process(bytes);
            var result = cRC64.Result();

            Console.WriteLine("result: {0:X16}", result);
        }

        static void ComputeSomeCRC(CRC32 crc32)
        {
            byte[] bytes = new byte[128];
            bytes[1] = bytes[123] = bytes[4] = 5;
            crc32.Process(bytes);
            var result = crc32.Result();

            Console.WriteLine("result: {0:X8}", result);
        }
    }
}

/*
result: E202E027
result: 6E59DCB2
result: 3D955EBB
result: E3FF5C4C
result: 54771FFD8FFA9270
result: 7DF448BC7FE9A2D0
 */
```