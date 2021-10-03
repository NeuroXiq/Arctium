```cs
class Program
    {
        static void Main()
        {
            JH_224 jh224 = new JH_224();
            JH_256 jh256 = new JH_256();
            JH_384 jh384 = new JH_384();
            JH_512 jh512 = new JH_512();

			// This is a 64-bit input from 'ShortMsgKAT'
            byte[] inputBytes = new byte[] { 0x4A, 0x4F, 0x20, 0x24, 0x84, 0x51, 0x25, 0x26 };

            jh224.HashBytes(inputBytes);
            jh256.HashBytes(inputBytes);
            jh384.HashBytes(inputBytes);
            jh512.HashBytes(inputBytes);

            byte[] hash224 = jh224.HashFinal();
            byte[] hash256 = jh256.HashFinal();
            byte[] hash384 = jh384.HashFinal();
            byte[] hash512 = jh512.HashFinal();


            Console.WriteLine("* JH 224 *");

            MemDump.HexDump(hash224);
            Console.WriteLine();

            Console.WriteLine("* JH 256 *");

            MemDump.HexDump(hash256);
            Console.WriteLine();

            Console.WriteLine("* JH 384 *");
            
            MemDump.HexDump(hash384);
            Console.WriteLine();

            Console.WriteLine("* JH 512 *");
            MemDump.HexDump(hash512);



            /* [OUTPUT]:
             * 
             * * JH 224 *
             *  E654E5ED 2EE87ED0 9FF7E1FF D1525B07
             *  A6C3A2F6 B34F7728 D1CC7088
             *  
             *  * JH 256 *
             *  2CF254D7 73DD18BA 2EFD3BE2 CB9C8F88
             *  AB313FB2 85DA11E3 8C8A6680 521DBB48
             *  
             *  
             *  * JH 384 *
             *  79DE2F45 888B898F 0DFC3167 B6FAFAD1
             *  F3B734C3 C81FAF5D E0C22C07 9EF740E1
             *  DEA2AC34 C56231D4 D99DCD9E 975A189B
             *  
             *  
             *  * JH 512 *
             *  11893879 DBC8E810 D3ABBA8F 38F07895
             *  C5B76C03 8D3BCDBC E71EDFFB 803233DD
             *  71066A7B AD4F4DE6 67C2F419 7731DC37
             *  736604EB F6825D71 6C491C84 41674E9C
             * 
             */
        }
    }
```