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
            PemFile pem = PemFile.FromString(RAWPEM_KEY_cert_secp256r1_sha256_1);
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
                Console.WriteLine("Named curve: {0}", !eccPrivateKey.Parameters.HasValue ? "<null>" : eccPrivateKey.Parameters.ToString());

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
         * [output]
         * Algorithms Id: ECPublicKey
         * Named curve: <null>
         * ECC Private key
         * FC9C5658 81156565 BB025722 F36A5ED9
         * 2CC2DB61 BAC3B2AE 5300A3E9 7CDE68C7
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