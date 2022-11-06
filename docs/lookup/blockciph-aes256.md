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
            byte[] key = new byte[32];
            byte[] toEncrypt = new byte[128];
            byte[] encrypted = new byte[128];
            byte[] decrypted = new byte[128];

            // create cipher
            AES aes = new AES(key);

            // encrypt
            aes.Encrypt(toEncrypt, 0, encrypted, 0, 128);

            // decrypt
            aes.Decrypt(encrypted, 0, decrypted, 0, 128);

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