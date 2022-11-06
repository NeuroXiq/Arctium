```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * 
 * 
 * HC_256 Does not work, dont use it
 * 
 */


using Arctium.Cryptography.Ciphers.StreamCiphers;
using Arctium.Shared.Helpers.Buffers;

namespace ConsoleAppTest
{
    internal class MainProgram
    { 
        static void Main()
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[32];
            byte[] toEncrypt = new byte[128];
            byte[] encrypted = new byte[128];
            byte[] decrypted = new byte[128];

            // create cipher
            HC_256 hc256 = new HC_256(key, iv);

            // encrypt
            hc256.Encrypt(toEncrypt, 0, encrypted, 0, 128);

            // decrypt
            hc256 = new HC_256(key, iv);
            hc256.Decrypt(encrypted, 0, decrypted, 0, 128);

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