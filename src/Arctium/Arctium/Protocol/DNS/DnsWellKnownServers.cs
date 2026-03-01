using Arctium.Protocol.DNS.Model;
using System.Net;

namespace Arctium.Protocol.DNS
{
    public class DnsServerInformational
    {
        public readonly string NSName;
        public readonly IPAddress IPv4Address;
        public readonly IPAddress IPv6Address;
        public readonly ResourceRecord[] AsResourceRecords;

        public DnsServerInformational(string name, IPAddress ipv4Address, IPAddress ipv6Address, ResourceRecord[] asResourceRecords)
        {
            NSName = name;
            IPv4Address = ipv4Address;
            IPv6Address = ipv6Address;
            AsResourceRecords = asResourceRecords;
        }
    }

    public class DnsWellKnownServers
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

        public static readonly IReadOnlyList<DnsRootServer> AllRootServers;

        public static readonly DnsServerInformational Google8888;
        public static readonly DnsServerInformational Google8844;

        public static ResourceRecord[] GetAllAsRecords()
        {
            var serversRecords = AllRootServers.SelectMany(t => new ResourceRecord[]
            {
                new ResourceRecord() { Class = QClass.IN, Type = QType.NS, Name = "", TTL = 1000, RData = new RDataNS(t.HostName) },
                new ResourceRecord() { Class = QClass.IN, Type = QType.A, Name = t.HostName, TTL = 1000, RData = new RDataA(t.IPv4Address.ToString()) },
                new ResourceRecord() { Class = QClass.IN, Type = QType.AAAA, Name = t.HostName, TTL = 1000, RData = new RDataAAAA(t.IPv6Address.GetAddressBytes()) },
            }).ToList();

            serversRecords.AddRange(Google8888.AsResourceRecords);
            serversRecords.AddRange(Google8888.AsResourceRecords);

            return serversRecords.ToArray();
        }

        static DnsWellKnownServers()
        {
            // google servers
            Google8888 = new DnsServerInformational(
                "dns.google",
                IPAddress.Parse("8.8.8.8"),
                null,
                new ResourceRecord[]
                {
                    new ResourceRecord() { Class = QClass.IN, Name = "", Type = QType.NS, RData = new RDataNS("dns.google"), TTL = 1000 },
                    new ResourceRecord() { Class = QClass.IN, Name = "dns.google", Type = QType.A, RData = new RDataA("8.8.8.8"), TTL = 1000 }
                });

            Google8844 = new DnsServerInformational(
                "dns.google",
                IPAddress.Parse("8.8.4.4"),
                null,
                new ResourceRecord[]
                {
                    new ResourceRecord() { Class = QClass.IN, Name = "", Type = QType.NS, RData = new RDataNS("dns.google"), TTL = 1000 },
                    new ResourceRecord() { Class = QClass.IN, Name = "dns.google", Type = QType.A, RData = new RDataA("8.8.4.4"), TTL = 1000 }
                });

            // root servers
            A = new DnsRootServer(
                'A',
                "a.root-servers.net",
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
                "b.root-servers.net",
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
                "c.root-servers.net",
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
                "d.root-servers.net",
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
                "e.root-servers.net",
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
                "f.root-servers.net",
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
                "g.root-servers.net",
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
                "h.root-servers.net",
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
                "i.root-servers.net",
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
                "j.root-servers.net",
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
                "k.root-servers.net",
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
                "l.root-servers.net",
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
                "m.root-servers.net",
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

            AllRootServers = new DnsRootServer[] { A, B, C, D, E, F, G, H, I, J, K, L, M };
        }
    }
}
