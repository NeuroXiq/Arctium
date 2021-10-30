```cs
//
// [Testing console program]
// Testing console program exclude from solution.
// Imports all Arctium dll, easy to check how something works
//



using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.FileFormat.PEM;
using Arctium.Standards.PKCS1.v2_2;
using System;
using System.Text;

/* 
 *
 * Examples for PKCS#1 v2.2 standard (PKCS1v2_2API.cs)
 *
 * Methods defined in API:
 * 
 * There are other method defined by standard and are also public if needed
 * 
 * - API offers following methods:
 * - OAEP Encryption (with customizable options)
 * - OEAP Decryption (with customizable options)
 * - RSASSA PSS Generate Signature (with customizable options) 
 * - RSASSA PSS Verify Signature (with customizable options)
 * - PKCS1 Encrypt
 * - PKCS1 Decrypt
 * - PKCS1 Generate signature (with customizable hash function)
 * - PKCS1 Verify Signature (with customizable hash function)
 *
 * Generated output is at the bottom of the file
 *
 * */

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {

        /// Private key can be represented in two variants: 
        /// 1. (d, n) pair (private exponent, modulus) -> PKCS1v2_2API.PrivateKeyNDPair
        /// 2. (dp, dq, qinv, n) -> PKCS1v2_2API.PrivateKeyCRT
        /// 
        /// To use method from standard, there is single representation for 
        /// private key: 'PKCS1v2_2API.PrivateKey' that takes one of the key
        /// representation metioned above by class constructor

        static PKCS1v2_2API.PublicKey publicKey;
        static PKCS1v2_2API.PrivateKey privateKey;

        static void Main()
        {
            PrepareAPIKeys();

            OEAP_ENCRYPT_DECRYPT_STANDARD();
            PSS_SIGNATURE_SIGN_VERIFY();

            PKCS1_ENCRYPT_DECRYPT();
            PKCS1_SIGNATURE_SIGN_VERIFY();

            OEAP_ENCRYPT_DECRYPT_CUSTOMIZED();
            PSS_SIGNATURE_SIGN_VERIFY_CUSTOMIZED(); 
            PKCS1_SIGNATURE_CUSTOMIZED();
        }

        static void OEAP_ENCRYPT_DECRYPT_STANDARD()
        {
            Console.WriteLine("\r\n-- OEAP ENCRYPT DECRYPT --");
            byte[] toEncrypt = Encoding.ASCII.GetBytes("Bytes to encrypt");
            
            // Defaults encryption with SHA1, label = null and MGF1
            
            byte[] encrypted = PKCS1v2_2API.RSAES_OAEP_ENCRYPT(publicKey, toEncrypt);
            Console.WriteLine("Encrypted Bytes: "); MemDump.HexDump(encrypted);

            // Default decryption with label = null, SHA1 and MGF1
            byte[] decrypted = PKCS1v2_2API.RSAES_OAEP_DECRYPT(privateKey, encrypted);
            Console.WriteLine("Decrypted Bytes: "); MemDump.HexDump(decrypted);
            Console.WriteLine("Decrypted as string: "); Console.WriteLine(Encoding.ASCII.GetString(decrypted));
        }

        static void PSS_SIGNATURE_SIGN_VERIFY()
        {
            Console.WriteLine("\r\n -- RSASSA_PSS SIGNATURE --");

            byte[] dataToSign = Encoding.ASCII.GetBytes("Some data to sign with private key");

            // Default sign method, seed length = 0, hash = SHA1 and MGF = MGF1
            byte[] signature = PKCS1v2_2API.RSASSA_PSS_SIGN(privateKey, dataToSign);
            Console.WriteLine("RSASSA_PSS Signature: "); MemDump.HexDump(signature);

            // Is signature valid?
            // Default verify: seed length: 0, hash = SHA1 and MGF = MGF1
            bool isSignatureValid = PKCS1v2_2API.RSASSA_PSS_VERIFY(publicKey, dataToSign, signature);
            Console.WriteLine("Is signature valid?: " + (isSignatureValid).ToString());
        }

        static void PKCS1_ENCRYPT_DECRYPT()
        {
            Console.WriteLine("\r\n-- RSA_PKCS1 ENCRYPT --");
            byte[] bytesToEncrypt = Encoding.ASCII.GetBytes("PKCS1 some bytes to encrypt");

            byte[] encrypted = PKCS1v2_2API.RSAES_PKCS1_v1_5_ENCRYPT(publicKey, bytesToEncrypt);
            Console.WriteLine("Encrypted bytes: "); MemDump.HexDump(encrypted);
            
            byte[] decrypted = PKCS1v2_2API.RSAES_PKCS1_v1_5_DECRYPT(privateKey, encrypted);
            Console.WriteLine("Decrypted bytes: "); MemDump.HexDump(decrypted);
            Console.WriteLine("Decrypted string: "); Console.WriteLine(Encoding.ASCII.GetString(decrypted));
        }

        static void PKCS1_SIGNATURE_SIGN_VERIFY()
        {
            Console.WriteLine("\r\n-- RSA PKCS1.5 SIGN VERIFY --");
            byte[] dataToSign = Encoding.ASCII.GetBytes("Some data to sign with pkcs 1.5");

            // Default hash function SHA1
            byte[] signature = PKCS1v2_2API.RSASSA_PKCS1_v1_5_GENERATE(privateKey, dataToSign);
            Console.WriteLine("Signature bytes: "); MemDump.HexDump(signature);

            // Verify
            bool isSignatureValid = PKCS1v2_2API.RSASSA_PKCS1_v1_5_VERIFY(publicKey, dataToSign, signature);
            Console.WriteLine("Is signature valid: " + isSignatureValid.ToString());
        }

        static void OEAP_ENCRYPT_DECRYPT_CUSTOMIZED()
        {
            // OAEP Hash function, Label and MGF can be customized
            // Mask generation function callback use specified hash function
            // Probably customization of MGF is not needed but Hash function can be usefull
        
            // Supported Hash function: All from Arctium Cryptography project
            // SHA2_224, SHA2_256, SHA3_512, JH_256 ... etc
            // remember to reset hash function after any operation (or create new one)!
            // MGF can be null (probably common usage is just a null), then default MGF1 will be used

            // Customizable options
            HashFunction customArctiumHashFunction = new SHA3_512();
            PKCS1v2_2API.MGF customMgf = CustomMaskGenerationFunction;
            byte[] customLabel = Encoding.ASCII.GetBytes("Some custom label for OAEP");
            
            Console.WriteLine("\r\n-- RSA OAEP Customized options --");

            byte[] toEncrypt = Encoding.ASCII.GetBytes("Customized OAEP bytes to encrypt");
            byte[] encrypted = PKCS1v2_2API.RSAES_OAEP_ENCRYPT(publicKey, toEncrypt, customLabel, customArctiumHashFunction, customMgf);

            Console.WriteLine("Custom encrypted data: "); MemDump.HexDump(encrypted);

            byte[] decrypted = PKCS1v2_2API.RSAES_OAEP_DECRYPT(privateKey, encrypted, customLabel, customArctiumHashFunction, customMgf);
            Console.WriteLine("Custom decrypted data: "); MemDump.HexDump(decrypted);
            Console.WriteLine("Custom decrypted data as string: "); Console.WriteLine(Encoding.ASCII.GetString(decrypted));
        }

        static byte[] CustomMaskGenerationFunction(HashFunction hashFunc, byte[] seed, int length)
        {
            // create some bytes, bytes must be always same for same seed and hashFunc
            // this is just an example. can be customized to any form (must return same value for same seed and hash)
            byte[] sampleBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
            byte[] currentHash = new byte[hashFunc.HashSizeBytes];
            byte[] maskToReturn = new byte[length];
            int remaining = length;

            for (int i = 0; i < length; i += hashFunc.HashSizeBytes)
            {
                if (i % hashFunc.HashSizeBytes == 0)
                {
                    hashFunc.HashBytes(sampleBytes);
                    hashFunc.HashBytes(currentHash);
                    currentHash = hashFunc.HashFinal();
                    hashFunc.Reset();
                }

                int toCopy = hashFunc.HashSizeBytes <= remaining ? hashFunc.HashSizeBytes : remaining;
                remaining -= toCopy;

                Buffer.BlockCopy(currentHash, 0, maskToReturn, i, toCopy);
            }
            
            // Reset or always create new instance
            hashFunc.Reset();

            return maskToReturn;
        }

        static void PSS_SIGNATURE_SIGN_VERIFY_CUSTOMIZED()
        {
            // Seed length, Hash function and Mask Generation Function (MGF) can be customized
            // Hash function must be one of the Arctium Hash Functions
            // Probably most common is to change hash function and MGF leave default to null (to use MGF1 as default in standard)

            // Customizable options
            int customSeedLength = 25;
            HashFunction customArctiumHashFunction = new SHA3_384();
            PKCS1v2_2API.MGF mgf = CustomMaskGenerationFunction;

            Console.WriteLine("\r\n-- RSASSA PSS Customized options signature --");

            byte[] bytesToSign = Encoding.ASCII.GetBytes("RSASSA_PSS bytes for custom signature");
            byte[] signature = PKCS1v2_2API.RSASSA_PSS_SIGN(privateKey, bytesToSign, customSeedLength, customArctiumHashFunction, mgf);
            
            Console.WriteLine("Customized RSASSA PSS Signature: "); MemDump.HexDump(signature);

            bool isSignatureValid = PKCS1v2_2API.RSASSA_PSS_VERIFY(publicKey, bytesToSign, signature, customSeedLength, customArctiumHashFunction, mgf);
            Console.WriteLine("Is RSASSA PSS Custom signature valid? " + isSignatureValid.ToString());
        
        }

        static void PKCS1_SIGNATURE_CUSTOMIZED()
        {
            // PKCS1 can have difference hash functions, supported:
            // SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512

            // Customizable options:
            PKCS1v2_2API.DigestInfoHashFunction customizedHashFunc = PKCS1v2_2API.DigestInfoHashFunction.SHA224;
            
            Console.WriteLine("\r\n-- PKCS1 Customized Signature --");
            
            byte[] toSign = new byte[] { 1, 2, 3, 4, 5, 6, };

            byte[] signature = PKCS1v2_2API.RSASSA_PKCS1_v1_5_GENERATE(privateKey, toSign, customizedHashFunc);
            
            Console.WriteLine("PKCS1 Customized signature, signature bytes: "); MemDump.HexDump(signature);

            bool isSignatureValid = PKCS1v2_2API.RSASSA_PKCS1_v1_5_VERIFY(publicKey, toSign, signature, customizedHashFunc);
            
            Console.WriteLine("PKCS1 Is Customized signature valid? " + isSignatureValid.ToString());
        }

        static void PrepareAPIKeys()
        {

            // If Key is represented in PEM file like following it can be decoded
            // using method below

            byte[] privateKeyBytes = PemFile.FromString(@"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----").DecodedData;
        
            // dp, dq, qint
           
            var rsaPrivateKey = PKCS1v2_2API.DecodePrivateKeyFromDerEncodedBytes(privateKeyBytes);
            var apiPrivateKeyCtr = new PKCS1v2_2API.PrivateKeyCRT(rsaPrivateKey);
            var apiPrivateKey = new PKCS1v2_2API.PrivateKey(apiPrivateKeyCtr);
            privateKey = apiPrivateKey;

            // or (d, n) pair
            
            byte[] d = new byte[] { 1, 2, 3 };
            byte[] n = new byte[] { 1, 2, 3 };
            var privateKeyNdPair = new PKCS1v2_2API.PrivateKeyNDPair(d, n);
            var apiPrivateKey2 = new PKCS1v2_2API.PrivateKey(privateKeyNdPair);


            // use Public Key from decoded private one
            var apiPublicKey = new PKCS1v2_2API.PublicKey(rsaPrivateKey.Modulus, rsaPrivateKey.PublicExponent);
            publicKey = apiPublicKey;

            // or
            
            byte[] pubN = new byte[] { 1, 2, 3, 4 };
            byte[] pubE = new byte[] { 1, 0, 0, 1 };
            var apiPublicKey2 = new PKCS1v2_2API.PublicKey(pubN, pubE);
        }


        /// public key if needed
static byte[] publicKeyData = PemFile.FromString(@"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvCgYxv7/MsUTyx9KIn+w
UkOWw6lNY3OH2Ea8adVPhWYhJerK7mH7PYNbsK/bVP2kbe8sIkVzNfsBogSScdWu
SRvnIL/Uldqe9xg+b3g67ZjcWA4R0jKRhDiysyh3xjCZ6p/SwvV41OgMsDr4Be5Y
0rK/x4SOPYK4zSe9Y/NYhYKXibP7TdJ01TjIfp3LrbIQ1NLkAq1MX/n7ObeRwfFY
Vmq5AzkDneH95o+KanQhxb7XUdcTAD9hxSIshGntGKTSRfFJR1LdnGU5GAOg65/i
ZoVfflzU/g4el4zoV7dXNVBP+3blJRS/uC8i3wcUyBCzT/AAr2oA2R4bh0gA0a/Q
MQIDAQAB
-----END PUBLIC KEY-----").DecodedData;
    }
}

/* * * *
* 
*    -- OEAP ENCRYPT DECRYPT --
*    Encrypted Bytes:
*    A86E220A 566C0C44 0512B332 F64C0BDF
*    DF2A36C1 3BC7FD27 508DBD6F 464A693C
*    1BD17C2E 04CE21DE 6F6B487B F2E663D1
*    535B3A21 606AAD17 9858584C B3B8D014
*    FDBCB61B 2577F9FA ABE642F2 8297FEE7
*    460A7751 5FC1CE5F 5B033D20 E4067C5A
*    0EB884FA 9F97A590 02C6CF0E 9C14C7BA
*    7A4C246B F1AFE410 22597B1F BBAB7873
*    0A0F9455 BF5B20E3 317AB189 F98C4D7E
*    18F3FF9A 59EAE8E2 7E138A68 767D54F6
*    8D8C6310 78287380 F7BD4414 FFD48F2F
*    9703C98E F7BC1E36 0222A993 4631E512
*    281F3969 94BF9DE4 8F7CF2DC 8772149F
*    D23EF508 346751D8 4CF92EA3 C97BE22D
*    C3A11A83 5F04FA87 C9F63DEB 9AC8F976
*    232FCD6C D1B54D44 0A32EB7F 4692CD01
*
*    Decrypted Bytes:
*    42797465 7320746F 20656E63 72797074
*
*    Decrypted as string:
*    Bytes to encrypt
*
*     -- RSASSA_PSS SIGNATURE --
*    RSASSA_PSS Signature:
*    6C96C227 7E573A04 824566C5 2BCF02C3
*    427BE055 72BFC918 7B17048E 05362DA3
*    FB6E1492 449F0F96 B45884A8 7B425760
*    5A050FE5 31C2A189 1BCB841A 0E397233
*    2FDF879F 13A26545 7BD890B2 064FC648
*    1348BB96 7CA03A38 A1A3F87E DD66C7AF
*    70CC8983 07667B12 BB1879D7 31AA8B8C
*    79250D81 B4CE650C B314D6CE 31B41412
*    FF1163B7 08CB7B8F 9D46B232 4CF4D0C3
*    21F1BE40 00D439F8 F1D0E591 94F7C0C6
*    E7043151 5CE8AA1D 3431AAFC DA0E2173
*    79D98013 DD5DEC13 1428631A 809A6991
*    71B825B0 F5FF9D53 2786CE53 D1CD79E2
*    771CA2DB 54AB988D D0053B59 2FEDF003
*    025DAA0F EAE4D1DD C124E03D 8ABB5402
*    26906270 1E3FA3FA 628C1346 179D5D8A
*
*    Is signature valid?: True
*
*    -- RSA_PKCS1 ENCRYPT --
*    Encrypted bytes:
*    A13A9D7B 53663452 9E470DBA 6E198556
*    660197C5 83049706 18E59891 86BE9DCA
*    A4EC97B9 E1682AA0 B37E4A41 3266C483
*    9310F33A 70D94F9A 6F0A0034 372153F9
*    1E9CC121 CB259CE2 FBE83211 1636589C
*    F55C58F7 4D3C84FA 55572841 95BD76F1
*    7956C3E2 8287F6DD 5DB33E95 B0FFFAF0
*    75D40B0A 3AFB8653 3A9014D7 4AB25C97
*    DE4C1E92 CD1FA65A 2D7A3A85 6FDF1A14
*    F3A826F5 482EE43C 1B25BEA0 80E619B7
*    AB0AFC56 0C1D91BC CF6F2AC2 E0FF1FCA
*    E0A44B33 CF7CA66B FBD3269C D3C04875
*    3DFC42B0 39FBEF20 80D1CF05 EC804F0B
*    AF3CF3D4 97AD982E F8AA72EE 84982A3D
*    D06E7E6E AAB37CBD 370AAD9A F2480999
*    094FA8B4 AC726079 3E9C7DF2 49CB2B83
*
*    Decrypted bytes:
*    504B4353 3120736F 6D652062 79746573
*    20746F20 656E6372 797074
*    Decrypted string:
*    PKCS1 some bytes to encrypt
*
*    -- RSA PKCS1.5 SIGN VERIFY --
*    Signature bytes:
*    2B489F50 535D701B 804401B2 FC3A5968
*    FE976300 97A590F3 90D6171A 3A3EE162
*    06995805 3A33AADC 0D964760 B4B2C931
*    B138DBAA 3E06EBC8 0E194E2A DDBF530E
*    2596A0A7 40FB603B E0351C8D AB167AB7
*    12C8ECF9 0ADA7D26 A136DE48 3270866F
*    E9BC1AEC A57FB50B 34632D1C 379CF04C
*    FBF5E593 0F0C37FE 73519599 BAD292A7
*    92D2310E 2DE48581 0B042E4C EDF7E41D
*    E47EC3C2 8A539CFD 95D1175B 00BD1C60
*    A9C9640E FB54A035 130847A9 6C728C2B
*    58C77D27 16C0DF90 49F7E18E 530FE6A8
*    3FBA1DFC B2E61A6F E09DA579 B86AA8E0
*    805AAE17 B70BF7CE 74406027 DE2BDD6B
*    5554CB55 60A3B289 062D3E0B 36E845CB
*    A7D6F183 78C437C4 4AA01826 A8977276
*
*    Is signature valid: True
*
*    -- RSA OAEP Customized options --
*    Custom encrypted data:
*    221F00A5 C02381BA 10F9F1D3 9132A7A1
*    08C04921 0C634362 63EAE430 95CEE98C
*    1F702E93 D4906D8C CC24C2AA 7AE38387
*    99EB99C6 5468F66F 01FAD1F7 03763EA8
*    25A8943B EEFE56A6 6CBE94C2 9DB725E6
*    8088D663 1821823A 6632CAED 15C7B80A
*    30566039 34D5EC19 C028C069 7330A576
*    93495B8A 3A09E2A4 44D17C67 BBBBE917
*    E8602950 70012B62 228150FC 5FC7EA5B
*    07273872 0B4DC968 C24BC3E6 85C40E59
*    05B4E738 A55C018A 231680D2 45CE5900
*    92213BAE B2F1E68A 35518B4A 2A95C6D7
*    69C652AB 53721BA0 E2366660 4C56D1BE
*    B04AC1D8 66E56FD6 13A14D73 8EB01114
*    FC6A0363 7267AC6F EF779AD2 A38AA670
*    699CE3FF 996906FD 9D04E449 5F3F4927
*
*    Custom decrypted data:
*    43757374 6F6D697A 6564204F 41455020
*    62797465 7320746F 20656E63 72797074
*
*    Custom decrypted data as string:
*    Customized OAEP bytes to encrypt
*
*    -- RSASSA PSS Customized options signature --
*    Customized RSASSA PSS Signature:
*    0EEAEBE8 A180B38A 7AE353A4 85571423
*    0F6EE122 40EE38F2 E506918C B365791D
*    12963DEC 033AEFE7 A1A9785D 48F99FE3
*    916D8845 17DBEAC2 9A15C097 8358F079
*    23FB984D B91B6FEA E6244702 30E705D1
*    E1BF2514 804B5F7A 0CECA8F3 1BF9AD69
*    A4A2E3FD D1D4EB99 A073942D 23211CBE
*    22941A8C F0374721 BCE81776 1CCBED48
*    459EF37A 6021703F 9D8C7EA9 7FC78C19
*    ACFB2331 F4737E86 76F0306C 44F16826
*    11432B44 F7CAFA3F 4F8FC39D 779FDD39
*    57A2359F F8F7172F 5A94BBAF BE1C41E1
*    0ABC1B94 43CCC846 699ED2A2 29DF7724
*    D7FC5244 6280FE89 BE58C55F 267AD007
*    FEB1937D A85F68B7 B4445D4D 48A35FB6
*    2B17ABDD 72E80C78 D407D413 CB6020C4
*
*    Is RSASSA PSS Custom signature valid? True
*
*    -- PKCS1 Customized Signature --
*    PKCS1 Customized signature, signature bytes:
*    88D8EE22 E6EAFD93 B92F9A9B 079451A9
*    3D40365A A988938F AA5D3F93 010A7638
*    E71FD2A9 AD4E501D 190ECBCA 663938EB
*    A49E0366 526F82B3 6F86E9F1 0F07BFBB
*    34F8263D 003334A3 90DE094C 0D2E548B
*    A28A5EDD 021FAEC6 CE0F4820 A599CC79
*    E19194ED 1427E490 CCA2B958 E88EEAC6
*    A67EB551 866C4623 9B89A3E7 3A40F18A
*    3BC6CA12 4773FD62 E07164A5 8EC1F2F8
*    DF4C4189 2024D476 144993CB 8B3DD5E6
*    8FD659A6 BE92FFB0 62780CD5 5B71DB92
*    6157CC96 B57A03C4 801A1214 190D3A5A
*    FF45C90F 1A19FD0E F7C45F00 6288763E
*    A114C623 6C12C90E 966FA9E6 0871A1AC
*    3078B779 7DBCBF6A 8A00CAA7 50AD4E9F
*    3358A4EC C3A5A9D6 3D17167B A764B909
*
*    PKCS1 Is Customized signature valid? True
*
* * * * * * */
```

