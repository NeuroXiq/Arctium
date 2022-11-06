```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 *
 * 
 */

using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.FileFormat.PEM;
using Arctium.Standards.PKCS8.v12;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace ConsoleAppTest
{
    internal class MainProgram
    {
        static void Main()
        {
            PemFile pem = PemFile.FromString(RAWPEM_KEY_cert_resa_2048_sha256_1);
            var privateKey = PKCS8v12.FromPem(pem);

            Console.WriteLine("Algorithms Id: {0}", privateKey.PrivateKeyAlgorithmIdentifier.Algorithm.ToString());

            if (privateKey.PrivateKeyAlgorithmIdentifier.Algorithm == PublicKeyAlgorithmIdentifierType.RSAEncryption)
            {
                var rsaPrivkey = privateKey.PrivateKey.Choice_RSAPrivateKey();

                Console.WriteLine("Coefficient: ");
                MemDump.HexDump(rsaPrivkey.Coefficient);
                Console.WriteLine("Exponent1: ");
                MemDump.HexDump(rsaPrivkey.Exponent1);
                Console.WriteLine("Coefficient: ");
                MemDump.HexDump(rsaPrivkey.Exponent2);
                Console.WriteLine("Exponent2: ");
                MemDump.HexDump(rsaPrivkey.Modulus);
                Console.WriteLine("Modulus: ");
                MemDump.HexDump(rsaPrivkey.Prime1);
                Console.WriteLine("Prime1: ");
                MemDump.HexDump(rsaPrivkey.Prime2);
                Console.WriteLine("Prime2: ");
                Console.WriteLine(rsaPrivkey.Version);
            }
            else if (privateKey.PrivateKeyAlgorithmIdentifier.Algorithm == PublicKeyAlgorithmIdentifierType.ECPublicKey)
            {
                var eccPrivateKey = privateKey.PrivateKey.Choice_EllipticCurvePrivateKey();
                Console.WriteLine("Named curve: {0}", eccPrivateKey.Parameters.ToString());

                Console.WriteLine("ECC Private key");
                MemDump.HexDump(eccPrivateKey.PrivateKey);

                if (eccPrivateKey.PublicKey != null)
                {
                    Console.WriteLine("ECC Public key (is additional encoded): ");
                    MemDump.HexDump(eccPrivateKey.PublicKey);
                }

                // can be decoded into EC Point
                // but need to get ECC Domain parameters from named curve (they are specified in some enum)
                // var point = Arctium.Standards.EllipticCurves.SEC1_Fp.OctetStringToEllipticCurvePoint(eccPrivateKey.PrivateKey);
            }
            else
            {
                throw new NotSupportedException();
            }

        }

        /*
         * Algorithms Id: RSAEncryption
Coefficient:
00F02539 A9039407 D7547B27 11EA84E5
FE244A7E 955276D6 AD7F81A3 B3889F70
574B9A84 F0D2D4BB 6EA71110 98F11035
A5B2F7CB 3EBF2C06 77D0201B 3813FE20
014E2B80 3B0CC1AE 76EACA0D 8D676CE9
8201B8D3 A554373B F5E6DE2E AEE3EE08
031A2FF2 E4E72664 0B4D7BD1 3FB122A6
05877F67 D3ECEFEB 757998E0 C9243763
DE
Exponent1:
0093F14A 04FBEF95 77A9E49E 48A95946
A37ECCF7 B150EA55 536856C3 8C7D03EC
7B529DF2 E3B46913 ED24C4BB 95FB3127
2710B84D 49A637D8 53AA6558 CB8A05AA
2845CD21 BC45C114 266ECBCB 71309FDB
94F73C50 7C8E3331 3522BDC3 F1664BEA
DB655B75 97CE2444 D48B9568 42DD59AE
36F0B12C 2A379881 3E3E7070 6CFBAB26
C1
Coefficient:
3D358FDF CD661835 E493CD3B 8EE1B230
A705E33F 7CFDA3ED 6AFF359A AB893B23
F9BF4AC8 4E7A89E9 A760AB94 1560CE3F
0435C310 1A7AA102 707770AC 8A4E672D
1345338F 8D7039A2 B7355872 45BE8AF9
2034CBDC FB5BA44B 81633204 0B49C891
853F3B15 6BC7B1ED 0C7431F5 8F9CA978
FD2612A3 ACEE1E60 4D9A1EB8 182B3001

Exponent2:
00DE8AED EE950F2C 38F8ACF8 144427ED
F359D505 ABF44985 E3595CA5 8147337E
4B5F4DAF 613D8A29 C6FE3346 D7FE829B
556632B6 07EEB3C4 8FF0FBD6 A5B2819F
AA6C5D07 499BA881 F3EFC2E0 7EDB2EAC
B1DE07CE 13431DBE 945EEA9E D2AFC960
C354F58A 695C56A3 58129B0A 99431719
DEFDD700 A8C97D3F 520B07BA 2D418731
8159E57C 278C134B F425AFA1 532A0329
1041630A 92828BC9 EC135CD7 5E54C9BA
6FD9F6C8 B38E8A50 47F42897 0E81E838
5C5988C6 E7407083 3AB337BB C84465D7
F3B883C9 BC74724F F26FFE7B 85A47765
8014D651 1DECDE4F 360AA2C6 99115561
7BBEFF6F AF2C84A8 1D67347D 1C3FD0A5
3C775AD8 E0FCC2B1 FE5D3E40 890EF382
AD
Modulus:
00F2AF18 A54E26DD 7F059D6C DCADAFB9
718720D9 567B68EB C9DA5632 0D54E446
F0EC5FFF 30BEC655 3C8B573F D68587DB
A8302E88 5E3DBA7A E576C787 BF04B949
302F80B6 F61A6F18 8D172F39 E7FC0220
F0D83AB1 51B3D2E2 D594AD4E 86FC64FE
1953166B 914C8F3E 63F66D36 2F66CEF7
2FDF0A21 301B7E5D 7114B382 B349A9E5
6D
Prime1:
00EAC0EA 448371B3 B7153D26 95091146
4473DF8D FBB0605F 9100AB27 B2D5644B
76B993B9 299B5E53 F53B99B1 35B50C0A
10937CC0 CE95BBDB 85890454 E9DF5332
BFAD5664 FC2E04E6 6567E939 29AE463E
32812AD8 F49A41AC 3641E5EC 73F97EDB
F97ED010 9BE87756 1F9DBDD1 A4EFF92F
4E3DD421 B43F8C27 86E41C78 1F81020A
41
Prime2:
0
         */

        static readonly string RAWPEM_KEY_cert_resa_2048_sha256_1 =
        @"
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDeiu3ulQ8sOPis
+BREJ+3zWdUFq/RJheNZXKWBRzN+S19Nr2E9iinG/jNG1/6Cm1VmMrYH7rPEj/D7
1qWygZ+qbF0HSZuogfPvwuB+2y6ssd4HzhNDHb6UXuqe0q/JYMNU9YppXFajWBKb
CplDFxne/dcAqMl9P1ILB7otQYcxgVnlfCeME0v0Ja+hUyoDKRBBYwqSgovJ7BNc
115Uybpv2fbIs46KUEf0KJcOgeg4XFmIxudAcIM6sze7yERl1/O4g8m8dHJP8m/+
e4Wkd2WAFNZRHezeTzYKosaZEVVhe77/b68shKgdZzR9HD/QpTx3Wtjg/MKx/l0+
QIkO84KtAgMBAAECggEBANuqoyWneOyb58tErSyBhX16JK2OiHmycTGaI7wyPf/i
Ala6UO/f21ETRiYdupnNHkTctZWq50OVGbhcrf4/uQ0OHd29qKpybAk0gUh2reHF
SHbH0XekeqQV9N2E9gN/QhAwtsk9Xj+qBeOIWLRCr0TPp1R9RzYcNK2ymPFnBz2y
q3WBkY7q6j4Aj0E+UvjxvKxRXPd7LEymp8yXeHJYPt2qCYQvqWrVvSwxC+qf4foY
gyu4mTZM08LJRidd30sVarGCB6HSPxxRJsbJfUFs/Yi3dKCx4Ykf6Aivd48/Y5bX
2YGRi65ygoKKL4HW042RHfBPnfVa5GN9NdErerh3NgECgYEA8q8YpU4m3X8FnWzc
ra+5cYcg2VZ7aOvJ2lYyDVTkRvDsX/8wvsZVPItXP9aFh9uoMC6IXj26euV2x4e/
BLlJMC+AtvYabxiNFy855/wCIPDYOrFRs9Li1ZStTob8ZP4ZUxZrkUyPPmP2bTYv
Zs73L98KITAbfl1xFLOCs0mp5W0CgYEA6sDqRINxs7cVPSaVCRFGRHPfjfuwYF+R
AKsnstVkS3a5k7kpm15T9TuZsTW1DAoQk3zAzpW724WJBFTp31Myv61WZPwuBOZl
Z+k5Ka5GPjKBKtj0mkGsNkHl7HP5ftv5ftAQm+h3Vh+dvdGk7/kvTj3UIbQ/jCeG
5Bx4H4ECCkECgYEAk/FKBPvvlXep5J5IqVlGo37M97FQ6lVTaFbDjH0D7HtSnfLj
tGkT7STEu5X7MScnELhNSaY32FOqZVjLigWqKEXNIbxFwRQmbsvLcTCf25T3PFB8
jjMxNSK9w/FmS+rbZVt1l84kRNSLlWhC3VmuNvCxLCo3mIE+PnBwbPurJsECgYA9
NY/fzWYYNeSTzTuO4bIwpwXjP3z9o+1q/zWaq4k7I/m/SshOeonpp2CrlBVgzj8E
NcMQGnqhAnB3cKyKTmctE0Uzj41wOaK3NVhyRb6K+SA0y9z7W6RLgWMyBAtJyJGF
PzsVa8ex7Qx0MfWPnKl4/SYSo6zuHmBNmh64GCswAQKBgQDwJTmpA5QH11R7JxHq
hOX+JEp+lVJ21q1/gaOziJ9wV0uahPDS1LtupxEQmPEQNaWy98s+vywGd9AgGzgT
/iABTiuAOwzBrnbqyg2NZ2zpggG406VUNzv15t4uruPuCAMaL/Lk5yZkC0170T+x
IqYFh39n0+zv63V5mODJJDdj3g==
-----END PRIVATE KEY-----
";

        static readonly string RAWPEM_KEY_cert_secp256r1_sha256_1 =
       @"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/JxWWIEVZWW7Alci
82pe2SzC22G6w7KuUwCj6XzeaMehRANCAASASBvcKJEApoRFUk2drksYvmybQ+B8
G5BfD/+/rqOneClSvT8KP3D362FjDF6ORAzLPJUDlqvIi9iMexAN+SSh
-----END PRIVATE KEY-----

";
    }
}

/*
 */
```