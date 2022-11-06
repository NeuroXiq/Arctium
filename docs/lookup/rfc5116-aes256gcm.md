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
            byte[] key = new byte[32];
            byte[] toEncrypt = new byte[128];
            byte[] additionalAssociatedData = new byte[8];
            byte[] encrypted = new byte[128];
            byte[] computedAuthTag = new byte[64];
            byte[] decrypted = new byte[128];

            // create cipher
            AEAD aead = RFC5116_AEAD_Predefined.Create_AEAD_AES_256_GCM(key);

            // encrypt
            byte[] iv = new byte[12];

            aead.AuthenticatedEncryption(
                iv, 0, 12,
                toEncrypt, 0, 128,
                additionalAssociatedData, 0, 8,
                encrypted, 0,
                computedAuthTag, 0);

            // decrypt
            bool isAuthTagValid;
            aead.AuthenticatedDecryption(
                iv, 0, 12,
                encrypted, 0, 128,
                additionalAssociatedData, 0, 8,
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
 OUTPUT:

Encrypted:
CEA7403D 4D606B6E 074EC5D3 BAF39D18
726003CA 37A62A74 D1A2F58E 7506358E
DD4AB128 4D4AE17B 41E85924 470C36F7
4741CBE1 81BB7F30 617C1DE3 AB0C3A1F
D0C48F73 21A82D37 6095ACE0 419167A0
BCAF49B0 C0CEA62D E6BC1C66 545E1DAD
ABFA77CD 6E85DA24 5FB0BDC5 E52CFC29
BA0AE1AB 2837E0F3 6387B70E 93176012

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