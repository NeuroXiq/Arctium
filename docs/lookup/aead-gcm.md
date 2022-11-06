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
using Arctium.Standards.RFC;

namespace ConsoleAppTest
{
    internal class MainProgram
    { 
        static void Main()
        {
            byte[] key = new byte[16];
            byte[] toEncrypt = new byte[128];
            byte[] additionalAssociatedData = new byte[12];
            byte[] encrypted = new byte[128];
            byte[] computedAuthTag = new byte[64];
            byte[] decrypted = new byte[128];

            // create cipher
            int authTagLen = 16;
            AEAD aead = new GaloisCounterMode(new AES(key), authTagLen);

            // encrypt
            byte[] iv = new byte[12];

            aead.AuthenticatedEncryption(
                iv, 0, 6,
                toEncrypt, 0, 128,
                additionalAssociatedData, 0, 12,
                encrypted, 0,
                computedAuthTag, 0);

            // decrypt
            bool isAuthTagValid;
            aead.AuthenticatedDecryption(
                iv, 0, 6,
                encrypted, 0, 128,
                additionalAssociatedData, 0, 12,
                decrypted, 0,
                computedAuthTag, 0,
                out isAuthTagValid);


            Console.WriteLine("Encrypted: ");
            MemDump.HexDump(encrypted);
            Console.WriteLine("Decrypted: ");
            MemDump.HexDump(decrypted);
            Console.WriteLine("Is auth tag valid: {0}", isAuthTagValid);
        }
    }
}
/*
Encrypted:
789D8374 CECDBC55 096AC73E 0AA4E0A2
5A6C9B09 9157628D 908E232C 9E72702A
F88EF1AF 8C3259CA 1B56FFEB BDF55F36
A795AF12 DFC7E1AA 94A7BA5E 33D86DFE
E80B5B50 0E47F4DA 237C40D1 776BB76F
1D2A4F81 C9C1A0F4 C248FA4F CEE8330A
0EED4B23 F5DAA141 87CF236F 017A0F40
96C7ED5C D72EFBD0 E00C1394 EA527603

Decrypted:
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000

Is auth tag valid: True
 */
```