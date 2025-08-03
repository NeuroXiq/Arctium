using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public static class DnsRootServers
    {
        public static readonly DnsRootServer A;
        public static readonly DnsRootServer B;
        public static readonly DnsRootServer C;
        public static readonly DnsRootServer D;
        public static readonly DnsRootServer E;
        public static readonly DnsRootServer F;
        public static readonly DnsRootServer G;
        public static readonly DnsRootServer H;
        public static readonly DnsRootServer I;
        public static readonly DnsRootServer J;
        public static readonly DnsRootServer K;
        public static readonly DnsRootServer L;
        public static readonly DnsRootServer M;

        public static readonly IReadOnlyList<DnsRootServer> All;

        static DnsRootServers()
        {
            
            A = new DnsRootServer(
                'A',
                "198.41.0.4",
                "2001:503:ba3e::2:30",
                "AS19836, AS36619, AS36620, AS36622, AS36625, AS36631, AS64820",
                "ns.internic.net",
                "Verisign",
                "United States",
                "Distributed using anycast",
                "14/2",
                "NSD and Verisign ATLAS");


            B = new DnsRootServer(
                'B',
                "170.247.170.2",
                "2801:1b8:10::b",
                "AS394353",
                "ns1.isi.edu",
                "USC-ISI",
                "United States",
                "Distributed using anycast",
                "6/0",
                "BIND and Knot DNS"
                );


            C = new DnsRootServer(
                'C',
                "192.33.4.12",
                "2001:500:2::c",
                "AS2149",
                "c.psi.net",
                "Cogent Communications",
                "United States",
                "Distributed using anycast",
                "10/0",
                "BIND"
                );


            D = new DnsRootServer(
                'D',
                "199.7.91.13",
                "2001:500:2d::d",
                "AS10886",
                "terp.umd.edu\t",
                "University of Maryland",
                "United States",
                "Distributed using anycast",
                "22/127",
                "NSD"
                );


            E = new DnsRootServer(
                'E',
                "192.203.230.10",
                "2001:500:a8::e",
                "AS21556",
                "ns.nasa.gov",
                "NASA Ames Research Center",
                " United States",
                "Distributed using anycast",
                "117/137",
                "BIND and NSD"
                );


            F = new DnsRootServer(
                'F',
                "192.5.5.241",
                "2001:500:2f::f",
                "AS3557",
                "ns.isc.org",
                "Internet Systems Consortium",
                "United States",
                "Distributed using anycast",
                "119/119",
                "BIND and Cloudflare"
                );


            G = new DnsRootServer(
                'G',
                "192.112.36.4",
                "2001:500:12::d0d",
                "AS5927",
                "ns.nic.ddn.mil",
                "Defense Information Systems Agency",
                "United States",
                "Distributed using anycast",
                "6/0",
                "BIND"
                );


            H = new DnsRootServer(
                'H',
                "198.97.190.53",
                "2001:500:1::53",
                "AS1508",
                "aos.arl.army.mil",
                "U.S. Army Research Lab",
                "United States",
                "Distributed using anycast",
                "8/0",
                "NSD"
                );


            I = new DnsRootServer(
                'I',
                "192.36.148.17",
                "2001:7fe::53",
                "AS29216",
                "nic.nordu.net",
                "Netnod",
                "Sweden",
                "Distributed using anycast",
                "63/2",
                "BIND"
                );


            J = new DnsRootServer(
                'J',
                "192.58.128.30",
                "2001:503:c27::2:30",
                "AS26415,[8][30] AS36626, AS36628, AS36632",
                null,
                "Verisign",
                "United States",
                "Distributed using anycast",
                "63/55",
                "NSD and Verisign ATLAS"
                );


            K = new DnsRootServer(
                'K',
                "193.0.14.129",
                "2001:7fd::1",
                "AS25152",
                null,
                "RIPE NCC",
                "Netherlands",
                "Distributed using anycast",
                "70/3",
                "BIND, NSD and Knot DNS"
                );


            L = new DnsRootServer(
                'L',
                "199.7.83.42",
                "2001:500:9f::42",
                "AS20144",
                null,
                "ICANN",
                "United States",
                "Distributed using anycast",
                "165/0",
                "NSD and Knot DNS"
                );


            M = new DnsRootServer(
                'M',
                "202.12.27.33",
                "2001:dc3::35",
                "AS7500",
                null,
                "WIDE Project",
                "Japan",
                "Distributed using anycast",
                "4/1",
                "BIND"
                );

            All = new DnsRootServer[] { A, B, C, D, E, F, G, H, I, J, K, L, M };
        }
    }
}
