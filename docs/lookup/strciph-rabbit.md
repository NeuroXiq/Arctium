```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 */


using Arctium.Cryptography.Ciphers.StreamCiphers;
using Arctium.Shared.Helpers.Buffers;

namespace ConsoleAppTest
{
    internal class MainProgram
    { 
        static void Main()
        {
            byte[] key = new byte[16];
            byte[] iv = new byte[8];
            byte[] toEncrypt = new byte[128];
            byte[] encrypted = new byte[128];
            byte[] decrypted = new byte[128];

            // create cipher
            Rabbit rabbit = new Rabbit(key, iv);

            // encrypt
            rabbit.Encrypt(toEncrypt, 0, encrypted, 0, 128);

            // decrypt
            rabbit.Reset();
            rabbit.Decrypt(encrypted, 0, decrypted, 0, 128);

            Console.WriteLine("Encrypted: ");
            MemDump.HexDump(encrypted);
            Console.WriteLine("Decrypted: ");
            MemDump.HexDump(decrypted);
        }
    }
}
/*
 OUTPUT:
Encrypted:
C6A7275E F85495D8 7CCD5D37 6705B7ED
5F29A6AC 04F5EFD4 7B8F2932 70DC4A8D
2ADE822B 29DE6C1E E52BDB8A 47BF8F66
986057E7 A709C90E 22795956 C62A8DB4
53E30951 648A0ABA E645E6B9 8EA12439
8DC23094 20AE7ED9 9DA3FACD 6EFAD1D1
623B4213 868F1585 783E02FC 530539D2
3BE6E34B 4F05FCC4 563D9B7A 11B42D81

Decrypted:
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000

 
 
 */
```