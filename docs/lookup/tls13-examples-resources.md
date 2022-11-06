```cs
using Arctium.Standards.FileFormat.PEM;
using Arctium.Standards.PKCS8.v12;
using Arctium.Standards.X509.X509Cert;
using System.Net;
using System.Net.Sockets;

namespace ConsoleAppTest
{
    public class Tls13Resources
    {
        public static readonly X509CertWithKey CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1;
        public static readonly X509CertWithKey CERT_WITH_KEY_cert_secp256r1_sha256_1;
        public static readonly X509CertWithKey CERT_WITH_KEY_cert_secp384r1_sha384_1;


        static Tls13Resources()
        {
            CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1 = ParseCert(RAWPEM_CERT_cert_resa_2048_sha256_1, RAWPEM_KEY_cert_resa_2048_sha256_1);
            CERT_WITH_KEY_cert_secp256r1_sha256_1 = ParseCert(RAWPEM_CERT_cert_secp256r1_sha256_1, RAWPEM_KEY_cert_secp256r1_sha256_1);
            CERT_WITH_KEY_cert_secp384r1_sha384_1 = ParseCert(RAWPEM_CERT_cert_secp384r1_sha384_1, RAWPEM_KEY_cert_secp384r1_sha384_1);
        }

        public static NetworkStream NetworkStreamToExampleServer()
        {
            // socket to some server
            
            var ip = Dns.GetHostAddresses("www.github.com")[0];

            Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(new IPEndPoint(ip, 443));

            return new NetworkStream(socket);
        }

        static X509CertWithKey ParseCert(string cert, string key)
        {
            X509CertificateDeserializer deserializer = new X509CertificateDeserializer();
            var x509 = deserializer.FromPem(PemFile.FromString(cert));
            var keyparsed = PKCS8v12.FromPem(PemFile.FromString(key));

            return new X509CertWithKey(x509, keyparsed.PrivateKey);
        }

        // generated on https://certificatetools.com/

        static readonly string RAWPEM_KEY_cert_secp384r1_sha384_1 =
        @"
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCoZPC9kmR5sF0YWEFx
kilxhIq89K9wIpZ5QfGdkrZkyceWjSsi7JlvfJE0qb0CSmGhZANiAASyjY2vHLay
IUSup5iVekf8PFFrI6sDTOT4/hsy6bdnY8626xKWuigg2Y0ZC53hGoMEe/ZKigTr
sRnrAsmrQivaYK7AbvbFk7B2k8VB/x2A9HwIZxvLJ0y6D3idIC2CBjU=
-----END PRIVATE KEY-----

";

        static readonly string RAWPEM_CERT_cert_secp384r1_sha384_1 =
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


        static readonly string RAWPEM_KEY_cert_secp256r1_sha256_1 =
        @"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/JxWWIEVZWW7Alci
82pe2SzC22G6w7KuUwCj6XzeaMehRANCAASASBvcKJEApoRFUk2drksYvmybQ+B8
G5BfD/+/rqOneClSvT8KP3D362FjDF6ORAzLPJUDlqvIi9iMexAN+SSh
-----END PRIVATE KEY-----

";

        static readonly string RAWPEM_CERT_cert_secp256r1_sha256_1 =
       @"
-----BEGIN CERTIFICATE-----
MIICVTCCAfygAwIBAgIUbd+/gaeBWu0a4fZD4Rrg80GoSBkwCgYIKoZIzj0EAwIw
XTElMCMGA1UEAwwcd3d3LmFyY2l0dW0tdGVzdGNlcnQtZWNjLmNvbTELMAkGA1UE
BhMCUEwxFjAUBgNVBAgMDUxlc3NlciBQb2xhbmQxDzANBgNVBAcMBktyYWtvdzAe
Fw0yMjEwMjIwOTQ2NDhaFw0yNTEwMjEwOTQ2NDhaMF0xJTAjBgNVBAMMHHd3dy5h
cmNpdHVtLXRlc3RjZXJ0LWVjYy5jb20xCzAJBgNVBAYTAlBMMRYwFAYDVQQIDA1M
ZXNzZXIgUG9sYW5kMQ8wDQYDVQQHDAZLcmFrb3cwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASASBvcKJEApoRFUk2drksYvmybQ+B8G5BfD/+/rqOneClSvT8KP3D3
62FjDF6ORAzLPJUDlqvIi9iMexAN+SSho4GZMIGWMB0GA1UdDgQWBBQNWKAhNWNu
17Q8m5PBoQCmEHKu4zAfBgNVHSMEGDAWgBQNWKAhNWNu17Q8m5PBoQCmEHKu4zAO
BgNVHQ8BAf8EBAMCBaAwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MCIGA1UdEQQbMBmCF3d3dy5hY3RpdW0tdGVzdGNlcnQuY29tMAoGCCqGSM49BAMC
A0cAMEQCIG9NhayGUBGYIvUltkXP5//ZBJjXa4vplM9YsEo6ByH6AiBRcUIC5vHG
lBnq8WiChGv74UD6N5Vw+FwXJzMMAhJOzA==
-----END CERTIFICATE-----

";

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

        static readonly string RAWPEM_CERT_cert_resa_2048_sha256_1 =
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

```