```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 *
 * 
 */


using Arctium.Cryptography.Ciphers.EllipticCurves.Algorithms;
using Arctium.Cryptography.Utils;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.EllipticCurves;
using Arctium.Standards.EllipticCurves.SEC2;
using Arctium.Standards.FileFormat.PEM;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace ConsoleAppTest
{
    internal class MainProgram
    {
        static void Main()
        {
            byte[] data = new byte[123];
            var domainParams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp256r1);
            byte[] privateKey = SEC1_ECFpAlgorithm.EllipticCurveKeyPairGenerationPrimitive(domainParams, out var publicKey);

            var signature = SEC1_Fp.ECDSA_SigningOperation(domainParams, HashFunctionId.SHA2_256, data, privateKey);

            var ecdsa = new EcdsaSigValue(signature);
            var encoded = X509Util.ASN1_DerEncodeEcdsaSigValue(ecdsa);
            
            Console.WriteLine("Encoded as X509 Ecdsa-Sig-Value DER structure");
            MemDump.HexDump(encoded);


            // can also be decoded
            var decoded = X509Util.ASN1_DerDecodeEcdsaSigValue(encoded);
        }
    }
}

/*
Encoded as X509 Ecdsa-Sig-Value DER structure
30450221 00C4747F 4C5B8498 C48076D7
75345F8A A9C8F1C9 20C8BC79 535E5991
C508FD63 0C022006 787EB842 52704E6C
AB278D1F 4FB9A459 35DACE82 1E48A2DA
41E8303C 1E3D37
 */
```