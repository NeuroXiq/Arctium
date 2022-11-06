```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - EC Generate Signature / Validate Signature
 * 
 * How to use generating signature and validating signatures using elliptic curves
 * Example shows only one hash function and only one EllipticCruve parameters
 * But this parameters are enum values that can be changed as needed
 * so showing other curves signatures is redundant because
 * they are different only by predefined enum EllipticCurve and Hash Function.
 * All supported as defined in enum values.
 * 
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
        public static ECFpPoint PublicKey;
        public static Arctium.Standards.EllipticCurves.SEC1.ECSignature Signature;
        public static byte[] Data = new byte[] { 1, 2, 3, 4 };


        static void Main()
        {
            GenerateSignature();
            VerifySignature();

            /*
             * [Example Output]
             * > Generated EC Signature:
             * > R:
             * > EFCC0B05 E93816E7 97064E6F AB969CB6
             * > 5B9EAC7B E7A62DF0 8F27373D D07539AC
             * > 00
             * > S:
             * > E4721057 17DB35A8 51332AC1 7A7EA899
             * > DF313F95 3F67BAC6 BEB1EC99 48A1635E
             * > 
             * > 
             * > Validating Signature
             * > Is valid: True
             */
        }

        private static void VerifySignature()
        {
            var domainParams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp256r1);
            var signature = new ECSignature(Signature.R, Signature.S);

            bool isValid = SEC1_Fp.ECDSA_Verify(domainParams, HashFunctionId.SHA2_256, Data, PublicKey, signature);
            Console.WriteLine("Validating Signature");
            Console.WriteLine("Is valid: {0}", isValid);
        }

        private static void GenerateSignature()
        {
            var domainParams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp256r1);
            byte[] privateKey = SEC1_ECFpAlgorithm.EllipticCurveKeyPairGenerationPrimitive(domainParams, out PublicKey);

            Signature = SEC1_Fp.ECDSA_SigningOperation(domainParams, HashFunctionId.SHA2_256, Data, privateKey);

            Console.WriteLine("Generated EC Signature: ");
            Console.WriteLine("R: ");
            MemDump.HexDump(Signature.R.ToByteArray());
            Console.WriteLine("S: ");
            MemDump.HexDump(Signature.S.ToByteArray());
            Console.WriteLine();
        }
    }
}

```