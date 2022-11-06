```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * Crypto - ChaCha 20
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
            byte[] nonce = new byte[12];
            byte[] toEncrypt = new byte[128];
            byte[] encrypted = new byte[128];
            byte[] decrypted = new byte[128];

            // create cipher
            ChaCha20 chacha20 = new ChaCha20(key, nonce);
            
            // encrypt
            chacha20.Encrypt(toEncrypt, 0, encrypted, 0, 128);

            // decrypt
            chacha20.Reset();
            chacha20.Decrypt(encrypted, 0, decrypted, 0, 128);

            Console.WriteLine("Encrypted: ");
            MemDump.HexDump(encrypted);
            Console.WriteLine("Decrypted: ");
            MemDump.HexDump(decrypted);

            /*
             * > Encrypted:
             * > 9F07E7BE 5551387A 98BA977C 732D080D
             * > CB0F29A0 48E36569 12C6533E 32EE7AED
             * > 29B72176 9CE64E43 D57133B0 74D839D5
             * > 31ED1F28 510AFB45 ACE10A1F 4B794D6F
             * > 2D09A0E6 63266CE1 AE7ED108 1968A075
             * > 8E718E99 7BD362C6 B0C34634 A9A0B35D
             * > 01273768 1F7B5D0F 281E3AFD E458BC1E
             * > 73D2D313 C9CF94C0 5FF37162 40A248F2
             * > 
             * > Decrypted:
             * > 00000000 00000000 00000000 00000000
             * > 00000000 00000000 00000000 00000000
             * > 00000000 00000000 00000000 00000000
             * > 00000000 00000000 00000000 00000000
             * > 00000000 00000000 00000000 00000000
             * > 00000000 00000000 00000000 00000000
             * > 00000000 00000000 00000000 00000000
             * > 00000000 00000000 00000000 00000000
             */
        }
    }
}

```