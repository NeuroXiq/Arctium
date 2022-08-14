using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Standards;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System.Collections.Generic;

namespace Arctium.Tests.Standards
{
    [TestsClass]
    public class RFC7748_Tests
    {

        static RFC7748_Tests()
        {
            LoadVectorsFromRFC7748();
        }

        [TestMethod]
        public List<TestResult> Vectors_from_rfc7748_AliceBobKeyExchange_X448()
        {
            byte[] expectedSharedSecret = BinConverter.FromString("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
            byte[] expectedBobPubKey = BinConverter.FromString("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
            byte[] expectedAlicePubKey = BinConverter.FromString("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");

            byte[] alicePrivKey = BinConverter.FromString("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
            byte[] alicePubKey = RFC7748.X448_UCoord_5(alicePrivKey);
            byte[] bobPrivKey = BinConverter.FromString("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
            byte[] bobpubkey = RFC7748.X448_UCoord_5(bobPrivKey);


            byte[] computedSharedSecret = RFC7748.X448(alicePrivKey, bobpubkey);

            return new List<TestResult>()
            {
                new TestResult("x448-alice-bob-shared-key", MemOps.Memcmp(expectedSharedSecret, computedSharedSecret)),
                new TestResult("x448-alice-pub-key", MemOps.Memcmp(expectedAlicePubKey, alicePubKey)),
                new TestResult("x448-bob-pub-key", MemOps.Memcmp(expectedBobPubKey, bobpubkey))
            };
        }

        [TestMethod]
        public List<TestResult> Vectors_from_rfc7748_AliceBobKeyExchange_X22519()
        {
            byte[] expectedSharedSecret = BinConverter.FromString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
            byte[] expectedBobPubKey = BinConverter.FromString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
            byte[] expectedAlicePubKey = BinConverter.FromString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

            byte[] alicePrivKey = BinConverter.FromString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            byte[] alicePubKey = RFC7748.X25519_UCoord_9(alicePrivKey);
            byte[] bobPrivKey = BinConverter.FromString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            byte[] bobpubkey = RFC7748.X25519_UCoord_9(bobPrivKey);

            byte[] computedSharedSecret = RFC7748.X25519(alicePrivKey, bobpubkey);

            return new List<TestResult>()
            {
                new TestResult("x22519-alice-bob-shared-key", MemOps.Memcmp(expectedSharedSecret, computedSharedSecret)),
                new TestResult("x22519-alice-pub-key", MemOps.Memcmp(expectedAlicePubKey, alicePubKey)),
                new TestResult("x22519-bob-pub-key", MemOps.Memcmp(expectedBobPubKey, bobpubkey))
            };
        }

        [TestMethod(expectedDurationInSeconds: 600)]
        public List<TestResult> Vectors_from_rfc7748_onemilion_times()
        {
            byte[] x25519_k = BinConverter.FromString("0900000000000000000000000000000000000000000000000000000000000000");
            byte[] x25519_u = BinConverter.FromString("0900000000000000000000000000000000000000000000000000000000000000");

            byte[] x448_k = BinConverter.FromString("0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
            byte[] x448_u = BinConverter.FromString("0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

            byte[] x25519_result_1 = BinConverter.FromString("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
            byte[] x25519_result_1000 = BinConverter.FromString("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
            byte[] x25519_result_1000000 = BinConverter.FromString("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");

            byte[] x448_result_1 = BinConverter.FromString("3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113");
            byte[] x448_result_1000 = BinConverter.FromString("aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38");
            byte[] x448_result_1000000 = BinConverter.FromString("077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37");

            List<TestResult> results = new List<TestResult>();

            for (int i = 1; i <= 1000000; i++)
            {
                byte[] result = RFC7748.X25519(x25519_k, x25519_u);

                x25519_u = x25519_k;
                x25519_k = result;

                if (i == 1)
                {
                    results.Add(new TestResult("milion, x25519, 1", MemOps.Memcmp(x25519_k, x25519_result_1)));
                }
                else if (i == 1000)
                {
                    results.Add(new TestResult("milion, x25519, 1000", MemOps.Memcmp(x25519_k, x25519_result_1000)));
                }
                else if (i == 1000000)
                {
                    results.Add(new TestResult("milion, x25519, 1000000", MemOps.Memcmp(x25519_k, x25519_result_1000000)));
                }

                if (i % 10000 == 0)
                {
                    TestsEvents.RaiseProgressEvent(nameof(RFC7748_Tests), nameof(Vectors_from_rfc7748_onemilion_times), i / 20000);
                }
            }

            for (int i = 1; i <= 1000000; i++)
            {
                byte[] result = RFC7748.X448(x448_k, x448_u);

                x448_u = x448_k;
                x448_k = result;

                if (i == 1)
                {
                    results.Add(new TestResult("milion, x448, 1", MemOps.Memcmp(x448_k, x448_result_1)));
                }
                else if (i == 1000)
                {
                    results.Add(new TestResult("milion, x448, 1000", MemOps.Memcmp(x448_k, x448_result_1000)));
                }
                else if (i == 1000000)
                {
                    results.Add(new TestResult("milion, x448, 1000000", MemOps.Memcmp(x448_k, x448_result_1000000)));
                }

                if (i % 10000 == 0)
                {
                    TestsEvents.RaiseProgressEvent(nameof(RFC7748_Tests), nameof(Vectors_from_rfc7748_onemilion_times), (50 + (i / 20000)));
                }
            }

            return results;
        }

        [TestMethod]
        public List<TestResult> VectorsFromRFC7748()
        {
            var results = new List<TestResult>();

            foreach (var t in RFC7748_Vectors)
            {
                byte[] result = null;
                if (t.Curve == "448")
                {
                    result = RFC7748.X448(t.InputScalar, t.InputUCoordinate);
                }
                else
                {
                    result = RFC7748.X25519(t.InputScalar, t.InputUCoordinate);
                }

                results.Add(new TestResult(t.Name, MemOps.Memcmp(result, t.OutputUCoordinate)));
            }

            return results;
        }

        static void LoadVectorRFC7748OneMilionTimes()
        {
            RFC7748_VectorsOneMilionTimes = new List<ECTest>()
            {

            };
        }

        static void LoadVectorsFromRFC7748()
        {
            RFC7748_Vectors = new List<ECTest>()
            {
                new ECTest("25519", "case-1",
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
                
                new ECTest("25519", "case-2",
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
                
                new ECTest("448", "case-3",
                "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121" +
                "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
                
                "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9" +
                "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",

                "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f" +
                "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"),

                new ECTest("448", "case-4",
                "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5" +
                "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",

                "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b" +
                "165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",

                "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7" +
                "ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"),
            };

        }

        static List<ECTest> RFC7748_Vectors;
        static List<ECTest> RFC7748_VectorsOneMilionTimes;

        class ECTest
        {
            public byte[] InputScalar;
            public byte[] InputUCoordinate;
            public byte[] OutputUCoordinate;
            public string Curve;
            public string Name;

            public ECTest(string curve, string name, string inputScalar, string inputUCoord, string outputUCoord)
                : this(
                      curve,
                      name,
                      BinConverter.FromString(inputScalar),
                      BinConverter.FromString(inputUCoord),
                      BinConverter.FromString(outputUCoord))

            { }

            public ECTest(string curve, string name, byte[] inputScalar, byte[] inputUCoord, byte[] outputUCoord)
            {
                InputScalar = inputScalar;
                InputUCoordinate = inputUCoord;
                OutputUCoordinate = outputUCoord;
                Curve = curve;
                Name = name;
            }
        }
    }
}
