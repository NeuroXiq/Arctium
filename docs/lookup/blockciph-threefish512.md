```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * 
 * 
 * 
 */


using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Cryptography.Ciphers.StreamCiphers;
using Arctium.Shared.Helpers.Buffers;

namespace ConsoleAppTest
{
    internal class MainProgram
    { 
        static void Main()
        {
            byte[] key = new byte[64];
            byte[] toEncrypt = new byte[128];
            byte[] encrypted = new byte[128];
            byte[] decrypted = new byte[128];

            // create cipher
            Threefish_512 threefish = new Threefish_512(key);

            // encrypt
            byte[] tweak = new byte[16];
            threefish.Encrypt(toEncrypt, 0, encrypted, 0, tweak);

            // decrypt
            threefish.Decrypt(encrypted, 0, decrypted, 0, tweak);

            Console.WriteLine("Encrypted: ");
            MemDump.HexDump(encrypted);
            Console.WriteLine("Decrypted: ");
            MemDump.HexDump(decrypted);
        }
    }
}
/*
 OUTPUT:
 */
```