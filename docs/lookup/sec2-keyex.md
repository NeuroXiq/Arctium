```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - ECC SEC1 Key Exchange
 * 
 * How to exchange keys using SEC1 / SEC2 ECC standards scheme
 * Other parameters (as enum specified) can be used, but for this example
 * only singe curve is use because showig key exchange for 
 * other curves is reduntant - only parameters curve enum value changed.
 * 
 * Arbitrary curves are supported - need to create
 * domain parameters and use as in this example with predefined parameters
 */


using Arctium.Cryptography.Ciphers.EllipticCurves;
using Arctium.Cryptography.Ciphers.EllipticCurves.Algorithms;
using Arctium.Cryptography.Utils;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.EllipticCurves;
using Arctium.Standards.EllipticCurves.SEC2;

namespace ConsoleAppTest
{


    internal class MainProgram
    {
        static ECFpPoint bobPublicKey;
        static ECFpPoint alicePublicKey;
        static byte[] bobPrivateKey;
        static byte[] alicePrivateKey;

        static void Main()
        {
            BobCreateKeys();
            AliceCreateKeys();
            BobGetKeyFromAliceAndComputeSharedSecret();
            AliceGetKeyFromBobAndComputeSharedSecret();

            /*
             * [Example output]
             * > Bob computes shared secret:
             * > Bob shared secret:
             * > 29F63B2B 7F0760FB 21650FF5 DDE83E0F
             * > A88AF81D 2CF70320 228AAF6A 8ABDF493
             * > 
             * > Alice computes shared secret:
             * > Alice shared secret:
             * > 29F63B2B 7F0760FB 21650FF5 DDE83E0F
             * > A88AF81D 2CF70320 228AAF6A 8ABDF493
             */
        }

        static void BobGetKeyFromAliceAndComputeSharedSecret()
        {
            var domainParams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp256r1);

            byte[] sharedSecret = SEC1_ECFpAlgorithm.EllipticCurveDiffieHellmanPrimitive(domainParams, bobPrivateKey, alicePublicKey);

            Console.WriteLine("Bob computes shared secret: ");
            Console.WriteLine("Bob shared secret: ");
            MemDump.HexDump(sharedSecret);
        }

        static void AliceGetKeyFromBobAndComputeSharedSecret()
        {
            var domainParams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp256r1);

            byte[] sharedSecret = SEC1_ECFpAlgorithm.EllipticCurveDiffieHellmanPrimitive(domainParams, alicePrivateKey, bobPublicKey);

            Console.WriteLine("Alice computes shared secret: ");
            Console.WriteLine("Alice shared secret: ");
            MemDump.HexDump(sharedSecret);
        }

        private static void BobCreateKeys()
        {
            var domainParams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp256r1);

            bobPrivateKey = SEC1_ECFpAlgorithm.EllipticCurveKeyPairGenerationPrimitive(domainParams, out bobPublicKey);
        }

        private static void AliceCreateKeys()
        {
            var domainParams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp256r1);

            alicePrivateKey = SEC1_ECFpAlgorithm.EllipticCurveKeyPairGenerationPrimitive(domainParams, out alicePublicKey);
        }
    }
}

```