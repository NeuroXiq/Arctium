```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 *
 * 
 */


using Arctium.Cryptography.Ciphers.DiffieHellman;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.DiffieHellman;
using Arctium.Standards.EllipticCurves;
using Arctium.Standards.FileFormat.PEM;

namespace ConsoleAppTest
{
    internal class MainProgram
    {
        static readonly string ExamplePemFileString =
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

        static void Main()
        {
            PemFile pem = PemFile.FromString(ExamplePemFileString);

            Console.WriteLine("Begin label: {0}", pem.BeginLabel);
            Console.WriteLine("End label: {0}", pem.EndLabel);
            Console.WriteLine("Raw bytes Decoded Data: ");
            MemDump.HexDump(pem.DecodedData);

            
        }
    }
}
/*
Begin label: CERTIFICATE
End label: CERTIFICATE
Raw bytes Decoded Data:
30820293 30820219 A0030201 0202140B
B5F3AF4E E9F361D7 9E342F4B 52F32831
D142E130 0A06082A 8648CE3D 04030330
5D312530 23060355 04030C1C 7777772E
61726369 74756D2D 74657374 63657274
2D656363 2E636F6D 310B3009 06035504
06130250 4C311630 14060355 04080C0D
4C657373 65722050 6F6C616E 64310F30
0D060355 04070C06 4B72616B 6F77301E
170D3232 31303232 30393538 31365A17
0D323531 30323130 39353831 365A305D
31253023 06035504 030C1C77 77772E61
72636974 756D2D74 65737463 6572742D
6563632E 636F6D31 0B300906 03550406
1302504C 31163014 06035504 080C0D4C
65737365 7220506F 6C616E64 310F300D
06035504 070C064B 72616B6F 77307630
1006072A 8648CE3D 02010605 2B810400
22036200 04B28D8D AF1CB6B2 2144AEA7
98957A47 FC3C516B 23AB034C E4F8FE1B
32E9B767 63CEB6EB 1296BA28 20D98D19
0B9DE11A 83047BF6 4A8A04EB B119EB02
C9AB422B DA60AEC0 6EF6C593 B07693C5
41FF1D80 F47C0867 1BCB274C BA0F789D
202D8206 35A38199 30819630 1D060355
1D0E0416 0414DD73 9F29D81C 374DAED9
C1622420 6CFC8FD5 0D80301F 0603551D
23041830 168014DD 739F29D8 1C374DAE
D9C16224 206CFC8F D50D8030 0E060355
1D0F0101 FF040403 0205A030 20060355
1D250101 FF041630 1406082B 06010505
07030106 082B0601 05050703 02302206
03551D11 041B3019 82177777 772E6163
7469756D 2D746573 74636572 742E636F
6D300A06 082A8648 CE3D0403 03036800
30650230 10E191EC F9D0A7BC BF528D7E
9CC6EF94 7BF2E1AB 0AA138B3 665DC5D6
E5308AC6 FF071B24 A46556C8 B83CBC8C
9D2D1DF2 023100DA 61FB9422 DCA5C70A
95DFCD9D 09CCF90A 99398D83 F837E8E1
446EE181 536C8A40 AD6E7135 AC1FE926
A51E8C93 2697BF
             */
```