```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 *
 * 
 */


using Arctium.Cryptography.Ciphers.DiffieHellman;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.DiffieHellman;
using Arctium.Standards.EllipticCurves;

namespace ConsoleAppTest
{
    internal class MainProgram
    {
        private static byte[] alicePrivateKey;
        private static byte[] alicePublicKey;
        private static byte[] bobPrivateKey;
        private static byte[] bobPublicKey;

        static void Main()
        {
            AliceGenerateKey();
            BobGenerateKey();
            AliceComputeShared();
            BobComputeShared();

            // Enum value in method indicates which group to create
            // use other enum constant values to use other group

            /*
             * > Alice shared secret:
             * > 58824E7A 4759AA1A 48081031 9F645E8D
             * > 85100D70 2514B3A9 1D154A94 9EB019DC
             * > 5A332CBD E15CC850 C5A017AA 49511E50
             * > 0B27F236 8F35CCBF 5A4D7864 0FF6B75C
             * > 1BB048BF C18790AA 0F4845AA 9CD29D96
             * > D410FA4D 628ECD63 8684B73C B85AA840
             * > 3D631D5A 45A3449E E710D937 41E4BAD5
             * > 2C15D327 03F57B17 56A50F21 115F42EF
             * > D360252C 83F5FAC2 FEA8915A A83D9592
             * > 021B4B2B BDCE7B3B C04AE542 8D3F749A
             * > 51C70FBB A04FEED2 FD2FC808 691AFA36
             * > 6986A4E0 B299D8CB D680C1D6 2542168F
             * > 02D42792 A7F8312F AE2CCF8D AEC62E3D
             * > A1C8FAA0 716450F6 0001888F 7E062D46
             * > FA609170 B82CB030 9484FF6F 6A6BF4FD
             * > 5A0C7607 2B85620F D15A80D1 9E29BAA0
             * > 
             * > Bob shared secret:
             * > 58824E7A 4759AA1A 48081031 9F645E8D
             * > 85100D70 2514B3A9 1D154A94 9EB019DC
             * > 5A332CBD E15CC850 C5A017AA 49511E50
             * > 0B27F236 8F35CCBF 5A4D7864 0FF6B75C
             * > 1BB048BF C18790AA 0F4845AA 9CD29D96
             * > D410FA4D 628ECD63 8684B73C B85AA840
             * > 3D631D5A 45A3449E E710D937 41E4BAD5
             * > 2C15D327 03F57B17 56A50F21 115F42EF
             * > D360252C 83F5FAC2 FEA8915A A83D9592
             * > 021B4B2B BDCE7B3B C04AE542 8D3F749A
             * > 51C70FBB A04FEED2 FD2FC808 691AFA36
             * > 6986A4E0 B299D8CB D680C1D6 2542168F
             * > 02D42792 A7F8312F AE2CCF8D AEC62E3D
             * > A1C8FAA0 716450F6 0001888F 7E062D46
             * > FA609170 B82CB030 9484FF6F 6A6BF4FD
             * > 5A0C7607 2B85620F D15A80D1 9E29BAA0
             */
        }

        private static void AliceGenerateKey()
        {
            var ffdheParams = FFDHE_RFC7919.GetFFDHEParams(FFDHE_RFC7919.SupportedGroupRegistry.ffdhe2048);
            FFDHE.GeneratePrivateAndPublicKey(ffdheParams, out alicePrivateKey, out alicePublicKey);
        }

        private static void BobGenerateKey()
        {
            var ffdheParams = FFDHE_RFC7919.GetFFDHEParams(FFDHE_RFC7919.SupportedGroupRegistry.ffdhe2048);
            FFDHE.GeneratePrivateAndPublicKey(ffdheParams, out bobPrivateKey, out bobPublicKey);
        }

        private static void AliceComputeShared()
        {
            var ffdheParams = FFDHE_RFC7919.GetFFDHEParams(FFDHE_RFC7919.SupportedGroupRegistry.ffdhe2048);
            byte[] sharedSecret = FFDHE.ComputeSharedSecret(ffdheParams, alicePrivateKey, bobPublicKey);
            Console.WriteLine("Alice shared secret: ");
            
            MemDump.HexDump(sharedSecret);
        }

        private static void BobComputeShared()
        {
            var ffdheParams = FFDHE_RFC7919.GetFFDHEParams(FFDHE_RFC7919.SupportedGroupRegistry.ffdhe2048);
            byte[] sharedSecret = FFDHE.ComputeSharedSecret(ffdheParams, bobPrivateKey, alicePublicKey);
            Console.WriteLine("Bob shared secret: ");

            MemDump.HexDump(sharedSecret);
        }
    }
}
/*

 */
```