using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers;
using Arctium.Standards.FileFormat.PEM;
using Arctium.Standards.PKCS1.v2_2;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using pkcs1 = Arctium.Standards.PKCS1.v2_2.PKCS1v2_2API;

namespace Arctium.Tests.Standards.PKCS1
{
    [TestsClass]
    public class PKCSv2_2API_Tests
    {
        pkcs1.PrivateKey privateKey512;
        pkcs1.PublicKey publicKey512;
        pkcs1.PrivateKey privateKey1024;
        pkcs1.PublicKey publicKey1024;
        pkcs1.PrivateKey privateKey2048;
        pkcs1.PublicKey publicKey2048;
        pkcs1.PrivateKey privateKey4096;
        pkcs1.PublicKey publicKey4096;

        List<byte[]> messages;

        public PKCSv2_2API_Tests()
        {
            Setup();
        }

        [TestMethod]
        public List<TestResult> OnlyAPI_PKCS1v2_2_OEAP_EncryptDecrypt512() => this.API_EncryptDecrypt_OAEP(512);

        [TestMethod]
        public List<TestResult> OnlyAPI_PKCS1v2_2_OEAP_EncryptDecrypt1024() => this.API_EncryptDecrypt_OAEP(1024);

        [TestMethod]
        public List<TestResult> OnlyAPI_PKCS1v2_2_OEAP_EncryptDecrypt2048() => this.API_EncryptDecrypt_OAEP(2048);

        [TestMethod(120)]
        public List<TestResult> OnlyAPI_PKCS1v2_2_OEAP_EncryptDecrypt4096() => this.API_EncryptDecrypt_OAEP(4096);

        [TestMethod]
        public List<TestResult> OnlyAPI_PKCS1v2_2_PKCS1v2_2_EncryptDecrypt512() => this.API_EncryptDecrypt_PKCS1(512);

        [TestMethod]
        public List<TestResult> OnlyAPI_PKCS1v2_2_PKCS1v2_2_EncryptDecrypt1024() => this.API_EncryptDecrypt_PKCS1(1024);

        [TestMethod]
        public List<TestResult> OnlyAPI_PKCS1v2_2_PKCS1v2_2_EncryptDecrypt2048() => this.API_EncryptDecrypt_PKCS1(2048);

        [TestMethod(120)]
        public List<TestResult> OnlyAPI_PKCS1v2_2_PKCS1v2_2_EncryptDecrypt4096() => this.API_EncryptDecrypt_PKCS1(4096);

        [TestMethod]
        public List<TestResult> OnlyAPI_PKCS1v2_2_RSASSA_PSS512() => this.API_RSASSA_PSS(512);

        [TestMethod]
        public List<TestResult> OnlyAPI_PKCS1v2_2_RSASSA_PSS1024() => this.API_RSASSA_PSS(1024);

        [TestMethod]
        public List<TestResult> OnlyAPI_PKCS1v2_2_RSASSA_PSS2048() => this.API_RSASSA_PSS(2048);

        [TestMethod(120)]
        public List<TestResult> OnlyAPI_PKCS1v2_2_RSASSA_PSS4096() => this.API_RSASSA_PSS(4096);

        [TestMethod]
        public List<TestResult> Compatible_With_NET_Implementation512() => this.CompatibleWithNETImplementation_OEAP(512);

        [TestMethod]
        public List<TestResult> Compatible_With_NET_Implementation1024() => this.CompatibleWithNETImplementation_OEAP(1024);

        [TestMethod]
        public List<TestResult> Compatible_With_NET_Implementation2048() => this.CompatibleWithNETImplementation_OEAP(2048);

        [TestMethod]
        public List<TestResult> Compatible_With_NET_Implementation4096() => this.CompatibleWithNETImplementation_OEAP(4096);

        [TestMethod]
        public List<TestResult> Compatible_With_NET_RSASSA_PKCS512() => this.Compatible_With_NET_RSASSA_PKSC1(512);

        [TestMethod]
        public List<TestResult> Compatible_With_NET_RSASSA_PKCS1024() => this.Compatible_With_NET_RSASSA_PKSC1(1024);

        [TestMethod]
        public List<TestResult> ONLYAPI_RSASSA_PSS_SIGNANDVERITY_WITH_SALT()
        {
            List<TestResult> results = new List<TestResult>();
            pkcs1.PublicKey pk = null;
            pkcs1.PrivateKey priv = null;
            string tName = "";
            GetKeysBySize(1024, out pk, out priv);
            HashFunction[] hashFuncs = new HashFunction[]
                {
                    new Arctium.Cryptography.HashFunctions.Hashes.SHA1(),
                    new SHA2_224(),
                    new SHA2_384(),
                    new Arctium.Cryptography.HashFunctions.Hashes.SHA3_256()
                };

            List<KeyValuePair<string, string>> msgWithSignature = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("AAAAAAAAAA", "YomGUfe5Hn4iMDvpbe35iVFDGbIFPV5tBXV2uAv566aTvj4JPmmkKS6GBfXw9KeWVDoM/pyUSDg4NAqRZiRfaRbr87GqRFkRiotbu2p105EJz6LTxdTFKgu6DhQz8jmnSTUgipxVMaO3JR0isQgK+cEsM9ffM9DH/8PgrLfDLDo="),
                new KeyValuePair<string, string>("AAA","jSF45JjwiwDy6lHoRioZV++btu//HoarwVigt3MEDyrjgNVMtiCS4/Q3c4ROcVd5LiOAesw8pLwVm2SicKMBRUpxyajeHfDBPkWPqxrULX7Hmhht5S9utIl+Qg5LQ510Pa7/iRCoo1MMSoSwGBJmLY/D/cCmaJP0VXkSt4/dVhU="),
                new KeyValuePair<string, string>("A", "hOfEcUuph5hp1/hfKA8IgOKGL7/pbb7kUmqpDh1RIqBXJitx9xJaS0cXBZCvnTJVa8KkE5CdxIGt8MU8lmMLq92PgKa50A2QsszxXBlPMeeUDhy9yuKdEVbRbaq2Cpy3TG/x4IAhYcn8WoxIKoQ4BT5gat6TICazQU3sxE5UcMg="),
                new KeyValuePair<string, string>(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "F1NLnnybD4M/+V9T/xeXtbtuffsOvzq70DyQRc0p9Y4E/fG4KwoCVAhacbvAo1BkDqZTHYw6XVgBxy7AYfhxU4glYwAtNe5ULF+M61vu34CuMmsQB5D4rIV5ACT0/z/zAMVLttxr+/24kBaQx1kiDzinxxMxtOpeVd22XtPfJsc="),
            };

            foreach (var ms in msgWithSignature)
            {
                tName = $"PKCSv2_2_RSASSA_PSS / VERIFY / MsgLen: {ms.Key.Length}";
                byte[] msg = Encoding.ASCII.GetBytes(ms.Key);
                byte[] signature = Convert.FromBase64String(ms.Value);

                try
                {
                    bool success = pkcs1.RSASSA_PSS_VERIFY(pk, msg, signature, 20);
                    results.Add(new TestResult(tName, success));
                }
                catch (Exception e)
                {
                    results.Add(new TestResult(tName, e, false));
                }
            }

            // max hash len + seed len (max seed) + const 2
            List<byte[]> messages = GetMessages((384/8) + 10 + 2);


            for (int i = 0; i < messages.Count; i++)
            {
                HashFunction hf = hashFuncs[i % hashFuncs.Length];
                int seedLen = i % 11;
                byte[] toSign = messages[i];

                tName = $"PKCSv2_2_RSASSA_PSS SIGN & VERIFY (ONLY API) / {hf.GetType().Name}, seedlen: {seedLen}, msglen: {toSign.Length}";

                try
                {
                    byte[] signature = pkcs1.RSASSA_PSS_SIGN(priv, toSign, seedLen, hf);
                    bool success = pkcs1.RSASSA_PSS_VERIFY(pk, toSign, signature, seedLen, hf);

                    results.Add(new TestResult(tName, success));
                }
                catch (Exception e)
                {
                    results.Add(new TestResult(tName, e, false));
                }

                
            }

            return results;
        }

        private List<TestResult> Compatible_With_NET_RSASSA_PKSC1(int keysize)
        {
            List<TestResult> results = new List<TestResult>();
            pkcs1.PublicKey pk = null;
            pkcs1.PrivateKey priv = null;
            string tName = "";
            GetKeysBySize(keysize, out pk, out priv);
            int hlen = 20;
            List<byte[]> msgs = GetMessages((keysize / 8) - hlen - 2);
            RSACryptoServiceProvider netImplementation = new RSACryptoServiceProvider(keysize);
            ImportKey(priv, netImplementation);

            foreach (var toSign in msgs)
            {
                tName = $"PKCS1v2_2API / ONLYAPI / RSASSA_PSS_SIGN & VERIFY / KeySize: {keysize} / MsgSize: {toSign.Length}";

                try
                {
                    byte[] signed = pkcs1.RSASSA_PKCS1_v1_5_GENERATE(priv, toSign);
                    bool success = netImplementation.VerifyHash((new SHA1Managed().ComputeHash(toSign)), signed, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

                    results.Add(new TestResult(tName, success));
                }
                catch (System.Exception e)
                {
                    results.Add(new TestResult(tName, e, false));
                }
            }

            return results;
        }

        private List<TestResult> CompatibleWithNETImplementation_OEAP(int keysize)
        {
            List<TestResult> results = new List<TestResult>();
            pkcs1.PublicKey pk = null;
            pkcs1.PrivateKey priv = null;
            string tName = "";
            GetKeysBySize(keysize, out pk, out priv);

            HashFunction hf;
            RSAEncryptionPadding netPadding;

            hf = new Arctium.Cryptography.HashFunctions.Hashes.SHA1();
            netPadding = RSAEncryptionPadding.OaepSHA1;

            int hLen = hf.HashSizeBytes;

            List<byte[]> msgs = GetMessages((keysize / 8) - (2 * hLen) - 2);
            RSACryptoServiceProvider netImplementation = new RSACryptoServiceProvider(keysize);
            ImportKey(priv, netImplementation);

            foreach (var toEncrypt in msgs)
            {
                tName = $"PKCSv2_2API OEAP / COMPATIBLE WITH .NET / KeySize: {keysize} / MgsLenInBytes: {toEncrypt.Length}";

                try
                {
                    byte[] encrypted = pkcs1.RSAES_OAEP_ENCRYPT(pk, toEncrypt,hashFunction: hf);
                    byte[] decrypted = netImplementation.Decrypt(encrypted, netPadding);
                    bool success = MemOps.Memcmp(decrypted, toEncrypt);

                    results.Add(new TestResult(tName, success));
                }
                catch (System.Exception e)
                {

                    results.Add(new TestResult(tName, e, false));
                }
            }

            return results;
        }

        private void ImportKey(pkcs1.PrivateKey priv, RSACryptoServiceProvider netImpl)
        {
            var apiPrivateKeyCtr = priv.PrivateKeyCRT;

            netImpl.ImportParameters(new RSAParameters
            {
                D = apiPrivateKeyCtr.PrivateExponent.ToByteArray(true, true),
                Exponent = apiPrivateKeyCtr.PublicExponent.ToByteArray(true, true),
                DP = apiPrivateKeyCtr.Exponent1.ToByteArray(true, true),
                DQ = apiPrivateKeyCtr.Exponent2.ToByteArray(true, true),
                InverseQ = apiPrivateKeyCtr.Coefficient.ToByteArray(true, true),
                Modulus = apiPrivateKeyCtr.Modulus.ToByteArray(true, true),
                P = apiPrivateKeyCtr.Prime1.ToByteArray(true, true),
                Q = apiPrivateKeyCtr.Prime2.ToByteArray(true, true)
            });
        }

        private List<TestResult> API_RSASSA_PSS(int keysize)
        {
            List<TestResult> results = new List<TestResult>();
            pkcs1.PublicKey pk = null;
            pkcs1.PrivateKey priv = null;
            string tName = "";
            GetKeysBySize(keysize, out pk, out priv);
            int hlen = 20;

            foreach (var toSign in GetMessages((keysize / 8) - hlen - 2))
            {
                tName = $"PKCS1v2_2API / ONLYAPI / RSASSA_PSS_SIGN & VERIFY / KeySize: {keysize} / MsgSize: {toSign.Length}";

                try
                {
                    byte[] signed = pkcs1.RSASSA_PSS_SIGN(priv, toSign);
                    bool success = pkcs1.RSASSA_PSS_VERIFY(pk, toSign, signed);

                    results.Add(new TestResult(tName, success));
                }
                catch (System.Exception e)
                {
                    results.Add(new TestResult(tName, e, false));
                }
            }

            return results;
        }

        private byte[] RangeBytes(int i) { return Enumerable.Range(0, i).Select(inte => (byte)inte).ToArray(); }

        private List<TestResult> API_EncryptDecrypt_PKCS1(int keysize)
        {
            List<TestResult> results = new List<TestResult>();
            pkcs1.PublicKey pk = null;
            pkcs1.PrivateKey priv = null;
            string tName = "";
            GetKeysBySize(keysize, out pk, out priv);

            foreach (var toEncrypt in GetMessages((keysize / 8) - 11))
            {
                tName = $"PKCSv2_2API PKCS1 ENCODE/DECODE / KeySize: {keysize} / MgsLenInBytes: {toEncrypt.Length}";

                try
                {
                    byte[] encrypted = pkcs1.RSAES_PKCS1_v1_5_ENCRYPT(pk, toEncrypt);
                    byte[] decrypted = pkcs1.RSAES_PKCS1_v1_5_DECRYPT(priv, encrypted);
                    bool success = MemOps.Memcmp(decrypted, toEncrypt);

                    results.Add(new TestResult(tName, success));
                }
                catch (System.Exception e)
                {

                    results.Add(new TestResult(tName, e, false));
                }
            }

            return results;
        }

        private List<TestResult> API_EncryptDecrypt_OAEP(int keysize)
        {
            List<TestResult> results = new List<TestResult>();
            string testName = "";
            pkcs1.PublicKey pk = null;
            pkcs1.PrivateKey priv = null;
            HashFunction hash = new Arctium.Cryptography.HashFunctions.Hashes.SHA1();
            int hashLen = hash.HashSizeBytes;

            GetKeysBySize(keysize, out pk, out priv);
            List<byte[]> msgs = GetMessages((keysize / 8) - (2 * hashLen) - 2);

            foreach(byte[] toEncrypt in msgs)
            {
                testName = $"RSA OEAP / KEY SIZE: {keysize} / MsgLenInBytes: {toEncrypt.Length}";

                try
                {
                    byte[] encrypted = pkcs1.RSAES_OAEP_ENCRYPT(pk, toEncrypt, hashFunction: hash);
                    byte[] decrypted = pkcs1.RSAES_OAEP_DECRYPT(priv, encrypted, hashFunction: hash);
                    bool success = MemOps.Memcmp(toEncrypt, decrypted);

                    results.Add(new TestResult(testName, success));
                }
                catch (System.Exception e)
                {
                    results.Add(new TestResult(testName, e, false));
                }
            }

            return results;
        }

        private List<byte[]> GetMessages(int max)
        {
            List<byte[]> results = new List<byte[]>();
            max = 20 < max ? 20 : max;

            for (int i = 0; i <= max; i++)
            {
                results.Add(messages[i]);
                results.Add(messages[max - i]);
            }

            return results;
        }

        private void GetKeysBySize(int keysize, out pkcs1.PublicKey pub, out pkcs1.PrivateKey priv)
        {
            if (keysize == 512) {  pub = publicKey512; priv = privateKey512; }
            else if (keysize == 1024) { pub = publicKey1024; priv = privateKey1024; }
            else if (keysize == 2048) { pub = publicKey2048; priv = privateKey2048; }
            else if (keysize == 4096) { pub = publicKey4096; priv = privateKey4096; }
            else throw new System.Exception();
        }

        private void Setup()
        {
            Keys512();
            Keys1024();
            Keys2048();
            Keys4096();

            messages = new List<byte[]>();

            for (int i = 0; i < 512; i++) messages.Add(Enumerable.Range(0, i).Select(integer => (byte)integer).ToArray());
        }



        void Keys4096()
        {
            string priv = @"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";
            string publ = @"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyq6Bz7Z4JLD7/YGMpds0
Jay/6EgAi4uoyR7QY3PLqPXf23ibCiT9O3Cq3UxdQhYQ6synRVAVUvQQpvRXQbPH
HcVYu8Bz0/c8GBuayc6uUQ+TzaquGUcNzszfKjnR4EEQGdzJiGI97ggd+Jc0yOhe
57RRocmirM3tuNaSC2ybVdDwvg5Etdr3eE60x19w2LZCrZG/LODR49rxPN9UT3Dc
QF5SGJxaKfMvdzzxbHp38JOZAPMMNtRX0uNJJxJjngr955WhYglhXSdtpRkCEdl6
MaGci4zP7RYC67e/ciq9GhAE5vraLv8eERjfuxrEbVV6q1YZglxxDayoxnWqfYiW
r2wjlxPjYouHFaW+liDryW/gMuJhalFPgaVS30jr0gR0fsBnjCdHupPGyQJfEJQ/
qc+e3y13BIdXF1BAmGGKoHNfhTpfExztR4RRUsg2dMOD5qJMMbDPKNOblavDsCQb
wY2+FVaKDt8m/jDmLptGbSyK1V7X1TfvhmnyZvGBuYYHUVxu3oovPr0zF4wwFJaC
ZnTkCie0Jf0/2WOiikyjFNKIBQB1ub1vjpJmc/OxxjyhPrrppjrQOq+AGJSuuVNL
mrPZOZZfQWhlX1mCW7pvvprxDUJFtnejhUvvKr1jhyxhDtQWKrf1ZjVH7QlYDrvA
qkheOVGFBWMfAMaefYqONSUCAwEAAQ==
-----END PUBLIC KEY-----";

            byte[] privBytes = PemFile.FromString(priv).DecodedData;
            byte[] pubBytes = PemFile.FromString(publ).DecodedData;

            privateKey4096 = new pkcs1.PrivateKey(new pkcs1.PrivateKeyCRT(pkcs1.DecodePrivateKeyFromDerEncodedBytes(privBytes)));
            publicKey4096 = new pkcs1.PublicKey(privateKey4096.PrivateKeyCRT.Modulus.ToByteArray(true, true),
                privateKey4096.PrivateKeyCRT.PublicExponent.ToByteArray(true, true));
        }

        void Keys2048()
        {
            string priv = @"-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvCgYxv7/MsUTyx9KIn+wUkOWw6lNY3OH2Ea8adVPhWYhJerK
7mH7PYNbsK/bVP2kbe8sIkVzNfsBogSScdWuSRvnIL/Uldqe9xg+b3g67ZjcWA4R
0jKRhDiysyh3xjCZ6p/SwvV41OgMsDr4Be5Y0rK/x4SOPYK4zSe9Y/NYhYKXibP7
TdJ01TjIfp3LrbIQ1NLkAq1MX/n7ObeRwfFYVmq5AzkDneH95o+KanQhxb7XUdcT
AD9hxSIshGntGKTSRfFJR1LdnGU5GAOg65/iZoVfflzU/g4el4zoV7dXNVBP+3bl
JRS/uC8i3wcUyBCzT/AAr2oA2R4bh0gA0a/QMQIDAQABAoIBAQCOtuccQRv2OU9r
GP+VLT7jFssK+6ZsUZvvKrAMojQf3bg012M27vCu1qy8VpbJX13R2MCj+gOKJSo2
5rrhRw9b+qMTzw0C4QEEMMpiqFIiF3jB/WH9CkgffxXkGETI+eI0+SbWo3QUITJG
lWO8s+2BWv1l6yAsfbOIQKVBY7l4Aagg4okYYXzSFJ5BqdbE4Gk6Pzp+AkGB/LQT
Uoc3s+B3tEXjc7B0E1WI1rgf04JDiA+xe/xe+r2IrXxvo9/l6FYg0yu2iNktYrc0
KpWpQy0x0Ts5ViPDcuSTO7z5uKx/BltXpsV0GZygthcnL32oYMLT3vZkwM/rl5BA
AYU28xWVAoGBAPLvid+9P1lv39ELP185r6kqi0CYBS4aDJA88n2jQRm8+VEGHrf5
+TNDJuNLFdHM6W33UJsApkfWNsaqw/jzEHam05CUM84Ynr/sNKvdBR79xKwB3Guo
sWf09xjPX7wTXOeG43+/K83rY4xilG+4mm76bVZxhSp7OkqVHC+h1+0/AoGBAMZG
bClM1tVROW0q02nRXf8l8ZwBLR+6tlaw8uZ4Jez5dy/DQAZQAyFqGo8PHfKTuPjk
DpP/vzAXaeVjfFWAxNWbrfWLAVtnTomoI+GV9k0+O3yPF1S1vZLwovZu4J1f2V4t
DWdPNBA9Y/yNUNn4zhqTJXhAoKH/77vqa/A1OTaPAoGBANuCJ7Fb3a7hkHnh0Nwp
UpjnUTYHZr7WWL3H5FAzwDISd7CHeCBCpbJ1HeFIyiltHwr26gV0m8rTO2FdkYAT
mK+tZAMCdqDlzCOcuacFKYhsQlYtxE4e+lX1mYP4dQeK82pcjpmyUlFZPPTvajJc
umZGr57pKitNd0lG3FYJxgKfAoGBAIooVAHLOv9VI7C/4KShcN/zLpHH+Atd7OQn
VHnnSnX/tl8frCM56ZSE/JCmtfVrnb5AGzBhSnVWO0HNurtRiNZXLjYkcAOizoT5
FleASSm1rXmzs0whf0E+UC9rPzQpr6sBtY9BD0Qpotw+FBJuXh8CXV+XmNaJIiFM
zX2JeJ5dAoGAcjUUqmSrNqSei0BV6xkO15uN7eQw8CqtiO2aILkOwUR7X+RCKe1I
2Y/a+uPj2WORCXV5UVrVZrdg4HSCbUn1aQvHWlMn1vyeZxRrzgy6tcZIVm5ivKfd
R+jWQdId7ZU7w9PA8CcJxCnRdMBpY4tLUb35j5flGsn2eDDOV2yYotM=
-----END RSA PRIVATE KEY-----";

            string publ = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvCgYxv7/MsUTyx9KIn+w
UkOWw6lNY3OH2Ea8adVPhWYhJerK7mH7PYNbsK/bVP2kbe8sIkVzNfsBogSScdWu
SRvnIL/Uldqe9xg+b3g67ZjcWA4R0jKRhDiysyh3xjCZ6p/SwvV41OgMsDr4Be5Y
0rK/x4SOPYK4zSe9Y/NYhYKXibP7TdJ01TjIfp3LrbIQ1NLkAq1MX/n7ObeRwfFY
Vmq5AzkDneH95o+KanQhxb7XUdcTAD9hxSIshGntGKTSRfFJR1LdnGU5GAOg65/i
ZoVfflzU/g4el4zoV7dXNVBP+3blJRS/uC8i3wcUyBCzT/AAr2oA2R4bh0gA0a/Q
MQIDAQAB
-----END PUBLIC KEY-----";

            byte[] privBytes = PemFile.FromString(priv).DecodedData;
            byte[] pubBytes = PemFile.FromString(publ).DecodedData;

            privateKey2048 = new pkcs1.PrivateKey(new pkcs1.PrivateKeyCRT(pkcs1.DecodePrivateKeyFromDerEncodedBytes(privBytes)));
            publicKey2048 = new pkcs1.PublicKey(privateKey2048.PrivateKeyCRT.Modulus.ToByteArray(true, true),
                privateKey2048.PrivateKeyCRT.PublicExponent.ToByteArray(true, true));
        }

        void Keys512()
        {
            string priv = @"-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAIj2QhV1oBSf2gIVpF7t3BkL9z8HUIrcs41f5gRrjwH75BE99wnC
YfzO9gV1gtSLPD/B7gdU9nzRl4Le+pbd6VcCAwEAAQJAVYmG6CQYIAldfGPLzkW7
aiEg/0owMSl5MdgsraIHJHMZZjlZkSgHKOBpgVTi82duJwx/5Y0kcbj1mNZZPlbZ
EQIhAP8lwrJe5B8Nki+v77U2FryczHyZl8lLl8AcmGQJ0irVAiEAiWtodKyo2GnR
PlxwErFXbhiA1tpGQ7QQIKq9HKUWgXsCIQDYTyIN6KbLsMyzwxuc7JtAEkrGg8yM
Kpsfkt6bSTw1dQIgWwGg2bQG1duuUUhSiG6d4jGkEaXYZrn2/EtWloPWVcUCICV3
RYqvgL58vO3f3thBiZvg18okh0EU84kQDCzs+uGr
-----END RSA PRIVATE KEY-----";
            string publ = @"-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIj2QhV1oBSf2gIVpF7t3BkL9z8HUIrc
s41f5gRrjwH75BE99wnCYfzO9gV1gtSLPD/B7gdU9nzRl4Le+pbd6VcCAwEAAQ==
-----END PUBLIC KEY-----";

            byte[] privBytes = PemFile.FromString(priv).DecodedData;
            byte[] pubBytes = PemFile.FromString(publ).DecodedData;

            privateKey512 = new pkcs1.PrivateKey(new pkcs1.PrivateKeyCRT(pkcs1.DecodePrivateKeyFromDerEncodedBytes(privBytes)));
            publicKey512 = new pkcs1.PublicKey(privateKey512.PrivateKeyCRT.Modulus.ToByteArray(true, true),
                privateKey512.PrivateKeyCRT.PublicExponent.ToByteArray(true, true));
        }

        void Keys1024()
        {
            string priv =
            @"-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCODOSDPae08MhpZIVpNNbICE4Pflp80KXwJz3y6sQ3nOxD7eaa
Me3nsGL6Sx22P3ZaKRIgDe5n5MjBMmhp9Z2G07Z+RuGMQtJ2r0Dpo6l6d+UPuWq/
D5T8/2H5oUktCcZkldFStAgRbcPRm2qoh3aMxtf1BQM3+A3jvGOYAr2REQIDAQAB
AoGAfCYseb+jGXLv1ZzzNLXnmcAYaVYnQ7sfrDq/29TvVSOjIuODjfRhVwNEHjkU
aLoieD45Bybl3IuKIcAqnaD64RHRqa7vk5Qsn0F+kFZLJJ/6icZ3zM6Kg7IpXFkl
fJYp6s3YscGSivK8yepGk6zMwfhpLnd2+1nnoH4+mVSfp5kCQQDXTBjFjVJP/ox7
BzndnMPF3C0gx10mC+dQQCtGWlAfYI3cuDu4+I8SwBR8fLyPl0MYh32thAhpyNv6
j9DchGo7AkEAqOfPmQwPhpzxg/X1Jznwr42uk5bzpl82ymZY0ycLfRdXoaK//tcj
b97BemzjuHCsx+Rmf4J2ciTEp1hxAk1xIwJBALoV/s85b+zOYhOwUjaW2au5u5O6
XWuWHE+DtyOuydPk+5jL8GrXA6q8NLjIg55EqmyYJ2uDVFZCksgF6AvBs6MCQFxf
EhBwIRmMQSTa4SyHqlJH2L6MYkmNbsh3+oHXq5fIqTsTZ462F4I5v3P1kwAuVr+m
8EsxjRdVdlrSqlMJCSMCQBeAEUT2wSSFPnKshfrku9qGNqryQR3hdRhV7VWw01/M
8/y5DW4aZKdelz5N0o2q7ypOZ8s6mvi4v3oJCDTYzbg=
-----END RSA PRIVATE KEY-----";

            string publ =
            @"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCODOSDPae08MhpZIVpNNbICE4P
flp80KXwJz3y6sQ3nOxD7eaaMe3nsGL6Sx22P3ZaKRIgDe5n5MjBMmhp9Z2G07Z+
RuGMQtJ2r0Dpo6l6d+UPuWq/D5T8/2H5oUktCcZkldFStAgRbcPRm2qoh3aMxtf1
BQM3+A3jvGOYAr2REQIDAQAB
-----END PUBLIC KEY-----";

            byte[] privBytes = PemFile.FromString(priv).DecodedData;
            byte[] pubBytes = PemFile.FromString(publ).DecodedData;

            privateKey1024 = new pkcs1.PrivateKey(new pkcs1.PrivateKeyCRT(pkcs1.DecodePrivateKeyFromDerEncodedBytes(privBytes)));
            publicKey1024 = new pkcs1.PublicKey(privateKey1024.PrivateKeyCRT.Modulus.ToByteArray(true, true),
                privateKey1024.PrivateKeyCRT.PublicExponent.ToByteArray(true, true));
        }
    }
}
