```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 *
 * 
 */


using Arctium.Cryptography.Utils;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.FileFormat.PEM;
using Arctium.Standards.X509.X509Cert;

namespace ConsoleAppTest
{
    internal class MainProgram
    {
        static void Main()
        {
            X509CertificateDeserializer x509deserialize = new X509CertificateDeserializer();

            PemFile pem = PemFile.FromString(X509Certificate_secp384r1_sha384_1);

            X509Certificate cert = x509deserialize.FromPem(pem);

            if (cert.SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm == Arctium.Standards.X509.X509Cert.Algorithms.PublicKeyAlgorithmIdentifierType.RSAEncryption)
            {
                var rsa = cert.SubjectPublicKeyInfo.PublicKey.Choice_RSAEncryption();
                Console.WriteLine("RSA");
                Console.WriteLine("Modulus: ");
                MemDump.HexDump(rsa.Modulus);

                Console.WriteLine("Exponent: ");
                MemDump.HexDump(rsa.PublicExponent);
            }
            else if (cert.SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm == Arctium.Standards.X509.X509Cert.Algorithms.PublicKeyAlgorithmIdentifierType.ECPublicKey)
            {
                var namedCurve = cert.SubjectPublicKeyInfo.AlgorithmIdentifier.Parameters.Choice_EcpkParameters().Choice_NamedCurve();
                var eccPublicKey = cert.SubjectPublicKeyInfo.PublicKey.Choice_ECPublicKey();

                Console.WriteLine("Public key Named Curve: {0}", namedCurve);
                MemDump.HexDump(eccPublicKey);
            }
            else
            {
                throw new NotSupportedException();
            }
        }


        /*
         * [output]
         * > Public key Named Curve: secp384r1
         * > 04B28D8D AF1CB6B2 2144AEA7 98957A47
         * > FC3C516B 23AB034C E4F8FE1B 32E9B767
         * > 63CEB6EB 1296BA28 20D98D19 0B9DE11A
         * > 83047BF6 4A8A04EB B119EB02 C9AB422B
         * > DA60AEC0 6EF6C593 B07693C5 41FF1D80
         * > F47C0867 1BCB274C BA0F789D 202D8206
         * > 35
         */

        static readonly string X509Certificate_secp384r1_sha384_1 =
        @"
-----BEGIN CERTIFICATE-----
MIICkzCCAhmgAwIBAgIUC7Xzr07p82HXnjQvS1LzKDHRQuEwCgYIKoZIzj0EAwMw
XTElMCMGA1UEAwwcd3d3LmFyY2l0dW0tdGVzdGNlcnQtZWNjLmNvbTELMAkGA1UE
BhMCUEwxFjAUBgNVBAgMDUxlc3NlciBQb2xhbmQxDzANBgNVBAcMBktyYWtvdzAe
Fw0yMjEwMjIwOTU4MTZaFw0yNTEwMjEwOTU4MTZaMF0xJTAjBgNVBAMMHHd3dy5h
cmNpdHVtLXRlc3RjZXJ0LWVjYy5jb20xCzAJBgNVBAYTAlBMMRYwFAYDVQQIDA1M
ZXNzZXIgUG9sYW5kMQ8wDQYDVQQHDAZLcmFrb3cwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAASyjY2vHLayIUSup5iVekf8PFFrI6sDTOT4/hsy6bdnY8626xKWuigg2Y0Z
C53hGoMEe/ZKigTrsRnrAsmrQivaYK7AbvbFk7B2k8VB/x2A9HwIZxvLJ0y6D3id
IC2CBjWjgZkwgZYwHQYDVR0OBBYEFN1znynYHDdNrtnBYiQgbPyP1Q2AMB8GA1Ud
IwQYMBaAFN1znynYHDdNrtnBYiQgbPyP1Q2AMA4GA1UdDwEB/wQEAwIFoDAgBgNV
HSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwIgYDVR0RBBswGYIXd3d3LmFj
dGl1bS10ZXN0Y2VydC5jb20wCgYIKoZIzj0EAwMDaAAwZQIwEOGR7PnQp7y/Uo1+
nMbvlHvy4asKoTizZl3F1uUwisb/BxskpGVWyLg8vIydLR3yAjEA2mH7lCLcpccK
ld/NnQnM+QqZOY2D+Dfo4URu4YFTbIpArW5xNawf6SalHoyTJpe/
-----END CERTIFICATE-----

";

        static readonly string X509Certificate_resa_2048_sha256_1 =
        @"
-----BEGIN CERTIFICATE-----
MIID4jCCAsqgAwIBAgIUYYet3/tggZHo5LuPTsOWeDt8M3owDQYJKoZIhvcNAQEL
BQAwXTElMCMGA1UEAwwcd3d3LmFyY2l0dW0tdGVzdGNlcnQtZWNjLmNvbTELMAkG
A1UEBhMCUEwxFjAUBgNVBAgMDUxlc3NlciBQb2xhbmQxDzANBgNVBAcMBktyYWtv
dzAeFw0yMjEwMjIxMDAxNDNaFw0yNTEwMjExMDAxNDNaMF0xJTAjBgNVBAMMHHd3
dy5hcmNpdHVtLXRlc3RjZXJ0LWVjYy5jb20xCzAJBgNVBAYTAlBMMRYwFAYDVQQI
DA1MZXNzZXIgUG9sYW5kMQ8wDQYDVQQHDAZLcmFrb3cwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDeiu3ulQ8sOPis+BREJ+3zWdUFq/RJheNZXKWBRzN+
S19Nr2E9iinG/jNG1/6Cm1VmMrYH7rPEj/D71qWygZ+qbF0HSZuogfPvwuB+2y6s
sd4HzhNDHb6UXuqe0q/JYMNU9YppXFajWBKbCplDFxne/dcAqMl9P1ILB7otQYcx
gVnlfCeME0v0Ja+hUyoDKRBBYwqSgovJ7BNc115Uybpv2fbIs46KUEf0KJcOgeg4
XFmIxudAcIM6sze7yERl1/O4g8m8dHJP8m/+e4Wkd2WAFNZRHezeTzYKosaZEVVh
e77/b68shKgdZzR9HD/QpTx3Wtjg/MKx/l0+QIkO84KtAgMBAAGjgZkwgZYwHQYD
VR0OBBYEFPYEGkRXuOVRGQ6ZKTPek0pvJMudMB8GA1UdIwQYMBaAFPYEGkRXuOVR
GQ6ZKTPek0pvJMudMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUBAf8EFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwIgYDVR0RBBswGYIXd3d3LmFjdGl1bS10ZXN0Y2VydC5j
b20wDQYJKoZIhvcNAQELBQADggEBADlS3K7PgHzun3KQ8wgQ8gDi37hqtgjYJGF6
Sah4d/R3jHbq4y/QGwsZYayCT9b9/d/0/cuveYFhwLsLvD8b3pXMlrtamh6QeH8K
+orK5a7c5SEwqfx/LP4x5WjYZhq2WvGXY+rRMscFbaYh+UMv8dPlm1zFvRiPRm2k
uAKEkIHDuJNBBERSmg3Qso3ATCVGlyjHb7jkzKXJrdCBjbe0iaswi7yr8j0UuiHm
f2f6ATLaK0T/ZIR/ZIn4U3PpgsRnqEqjLRzgHSjoqx/yr/Nb5E7sotGFsoczmbQz
WMUpP3z6UnjDRAsu+Yrfxe09A8EqHes2qN9wt5XkfqQY0fMIFiI=
-----END CERTIFICATE-----

";
    }
}

/*
 */
```