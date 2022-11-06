```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 *
 * 
 */


using Arctium.Cryptography.Utils;
using Arctium.Standards.FileFormat.PEM;
using Arctium.Standards.X509.X509Cert;

namespace ConsoleAppTest
{
    internal class MainProgram
    {
        static void Main()
        {
            X509CertificateDeserializer x509deserialize = new X509CertificateDeserializer();

            PemFile pem = PemFile.FromString(X509Certificate_resa_2048_sha256_1);

            X509Certificate cert = x509deserialize.FromPem(pem);

            Console.WriteLine("{0}: {1}", nameof(cert.Version), cert.Version);
            Console.WriteLine("{0}: {1}", nameof(cert.Extensions), cert.Extensions.Length);
            Console.WriteLine("{0}: {1}", nameof(cert.Subject), cert.Subject.ToString());
            Console.WriteLine("{0}: {1}", nameof(cert.ValidNotAfter), cert.ValidNotAfter);
            Console.WriteLine("{0}: {1}", nameof(cert.ValidNotBefore), cert.ValidNotBefore);
            Console.WriteLine("{0}: {1}", nameof(cert.SubjectPublicKeyInfo.AlgorithmIdentifier), cert.SubjectPublicKeyInfo.AlgorithmIdentifier.ToString());
            Console.WriteLine("{0}: {1}", nameof(cert.Issuer), cert.Issuer.ToString());


        }

        /* [output]
         * 
         * Version: 2
         * Extensions: 5
         * Subject: CN=www.arcitum-testcert-ecc.com, C=PL, SP=Lesser Poland, L=Krakow
         * ValidNotAfter: 10/21/2025 12:01:43 PM
         * ValidNotBefore: 10/22/2022 12:01:43 PM
         * AlgorithmIdentifier: Arctium.Standards.X509.X509Cert.Algorithms.PublicKeyAlgorithmIdentifier
         * Issuer: CN=www.arcitum-testcert-ecc.com, C=PL, SP=Lesser Poland, L=Krakow
         */

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