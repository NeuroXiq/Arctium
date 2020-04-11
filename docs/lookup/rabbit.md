```cs
using Arctium.Cryptography.Ciphers.StreamCiphers;
using System;
using System.Text;

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main()
        {
            // example bytes to encrypt

            byte[] plainData1 = Encoding.ASCII.GetBytes("Sample text - encryption without IV");
            byte[] plainData2 = Encoding.ASCII.GetBytes("Sample text - IV is present");
            
            // encrypted bytes buffers

            byte[] encryptedData1 = new byte[plainData1.Length];
            byte[] encryptedData2 = new byte[plainData2.Length];

            // decrypted bytes buffers

            byte[] decrypt1 = new byte[plainData1.Length];
            byte[] decrypt2 = new byte[plainData2.Length];



            // Create rabbit without iv 
            // example key as 16-zero bytes

            byte[] key1 = new byte[16];
            Rabbit rabbit1 = new Rabbit(key1);
            rabbit1.Encrypt(plainData1, 0, plainData1.Length, encryptedData1, 0);


            // create rabbit with IV 
            // and key (example key as 0 bytes)

            byte[] iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] key2 = new byte[16];
            Rabbit rabbit2 = new Rabbit(key2, iv);
            rabbit2.Encrypt(plainData2, 0, plainData2.Length, encryptedData2, 0);

            Console.WriteLine("Encrypted data without IV:");
            Console.WriteLine(BitConverter.ToString(encryptedData1));

            Console.WriteLine("Encrypted data with IV:");
            Console.WriteLine(BitConverter.ToString(encryptedData2));

            // Reset means that inner state of 
            // the cipher is exactly the same as a new instance.
            // Rabbit for decryption MUST be call reset because 
            // inner state changes over bytes encyption.

            rabbit1.Reset();
            rabbit2.Reset();

            rabbit1.Decrypt(encryptedData1, 0, encryptedData1.Length, decrypt1, 0);
            rabbit2.Decrypt(encryptedData2, 0, encryptedData2.Length, decrypt2, 0);

            string decrypted1 = Encoding.ASCII.GetString(decrypt1);
            string decrypted2 = Encoding.ASCII.GetString(decrypt2);

            Console.WriteLine("Decryption 1: " + decrypted1);
            Console.WriteLine("Decryption 2: " + decrypted2);

            // [output]
            //
            // Encrypted data without IV:
            // E2 - 36 - 39 - 80 - 5A - C0 - F6 - 98 - 90 - 13 - 31 - 06 - 31 - 6A - 92 - 6C - EB - 9A - A1 - 65 - B1 - F5 - 63 - 57 - 5B - 1E-05 - 33 - E1 - A9 - FF - D3 - D4 - 5F - F7
            // Encrypted data with IV:
            // D8 - 01 - 1F - DD - D4 - 2C - 4F - 8C - 71 - 1E-EF - 9C - 5E-F9 - 99 - FF - A2 - 4F - 11 - BD - EB - 7F - C7 - A5 - 51 - A3 - FE
            // Decryption 1: Sample text -encryption without IV
            // Decryption 2: Sample text -IV is present
        }
    }
}

```