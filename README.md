# Arctium - .NET Core Crypto Library
- - -
Download binaries archive: [Release-Link](https://github.com/NeuroXiq/Arctium/releases/tag/v0.0.0.9)

Nuget:
```
Install-Package Arctium.Shared
Install-Package Arctium.Cryptography
Install-Package Arctium.Standards
```
- - -
API Docs: \
https://dndocs.com/?packageName=Arctium.Shared&packageVersion=1.0.0.1 \
https://dndocs.com/?packageName=Arctium.Standards&packageVersion=1.0.0.1 \
https://dndocs.com/?packageName=Arctium.Cryptography&packageVersion=1.0.0.1 


Arctium is a simple crypto library, created and maintained for learning purpose. 
It provides various cryptographic functions, ciphers, connection protocols etc. implemented for better or worse but probably they should works.

## Projects
Solution is partitioned into  a following projects, each of them is a set of related algorithms. If you wish to get more informations about specific project, algorithm and examples, see appropriate [docs] folder. Each folder contains more specific informations and examples.

### ArctiumCLI 
In the future there may be some console interface utility tool 

### Look up documents
Following list shows all implemented features with links to examples

## Protocols

#### DNS
|RFC|Date|Description|Documentation with Examples|state|
|-|-|-|-|-|
|[RFC-9619](https://datatracker.ietf.org/doc/html/rfc9619)|July 2024|In the DNS, QDCOUNT Is (Usually) One|Docs todo|TODO|
|[RFC-9615](https://datatracker.ietf.org/doc/html/rfc9615)|July 2024|Automatic DNSSEC Bootstrapping Using Authenticated Signals from the Zone's Operator|Docs todo|TODO|
|[RFC-9606](https://datatracker.ietf.org/doc/html/rfc9606)|June 2024|DNS Resolver Information|Docs todo|TODO|
|[RFC-9567](https://datatracker.ietf.org/doc/html/rfc9567)|April 2024|DNS Error Reporting|Docs todo|TODO|
|[RFC-9558](https://datatracker.ietf.org/doc/html/rfc9558)|April 2024|Use of GOST 2012 Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC|Docs todo|TODO|
|[RFC-9539](https://datatracker.ietf.org/doc/html/rfc9539)|February 2024|Unilateral Opportunistic Deployment of Encrypted Recursive-to-Authoritative DNS|Docs todo|TODO|
|[RFC-9526](https://datatracker.ietf.org/doc/html/rfc9526)|January 2024|Simple Provisioning of Public Names for Residential Networks|Docs todo|TODO|
|[RFC-9520](https://datatracker.ietf.org/doc/html/rfc9520)|December 2023|Negative Caching of DNS Resolution Failures|Docs todo|TODO|
|[RFC-9499](https://datatracker.ietf.org/doc/html/rfc9499)|March 2024|DNS Terminology|Docs todo|TODO|
|[RFC-9471](https://datatracker.ietf.org/doc/html/rfc9471)|September 2023|DNS Glue Requirements in Referral Responses|Docs todo|TODO|
|[RFC-9432](https://datatracker.ietf.org/doc/html/rfc9432)|July 2023|DNS Catalog Zones|Docs todo|TODO|
|[RFC-9364](https://datatracker.ietf.org/doc/html/rfc9364)|February 2023|DNS Security Extensions (DNSSEC)|Docs todo|TODO|
|[RFC-9276](https://datatracker.ietf.org/doc/html/rfc9276)|August 2022|Guidance for NSEC3 Parameter Settings|Docs todo|TODO|
|[RFC-9267](https://datatracker.ietf.org/doc/html/rfc9267)|July 2022|Common Implementation Anti-Patterns Related to Domain Name System (DNS) Resource Record (RR) Processing|Docs todo|TODO|
|[RFC-9250](https://datatracker.ietf.org/doc/html/rfc9250)|May 2022|DNS over Dedicated QUIC Connections|Docs todo|TODO|
|[RFC-9230](https://datatracker.ietf.org/doc/html/rfc9230)|June 2022|Oblivious DNS over HTTPS|Docs todo|TODO|
|[RFC-9210](https://datatracker.ietf.org/doc/html/rfc9210)|March 2022|DNS Transport over TCP - Operational Requirements|Docs todo|TODO|
|[RFC-9199](https://datatracker.ietf.org/doc/html/rfc9199)|March 2022|Considerations for Large Authoritative DNS Server Operators|Docs todo|TODO|
|[RFC-9157](https://datatracker.ietf.org/doc/html/rfc9157)|December 2021|Revised IANA Considerations for DNSSEC|Docs todo|TODO|
|[RFC-9156](https://datatracker.ietf.org/doc/html/rfc9156)|November 2021|DNS Query Name Minimisation to Improve Privacy|Docs todo|TODO|
|[RFC-9120](https://datatracker.ietf.org/doc/html/rfc9120)|October 2021|Nameservers for the Address and Routing Parameter Area ("arpa") Domain|Docs todo|TODO|
|[RFC-9108](https://datatracker.ietf.org/doc/html/rfc9108)|September 2021|YANG Types for DNS Classes and Resource Record Types|Docs todo|TODO|
|[RFC-9103](https://datatracker.ietf.org/doc/html/rfc9103)|August 2021|DNS Zone Transfer over TLS|Docs todo|TODO|
|[RFC-9102](https://datatracker.ietf.org/doc/html/rfc9102)|August 2021|TLS DNSSEC Chain Extension|Docs todo|TODO|
|[RFC-9077](https://datatracker.ietf.org/doc/html/rfc9077)|July 2021|NSEC and NSEC3: TTLs and Aggressive Use|Docs todo|TODO|
|[RFC-9076](https://datatracker.ietf.org/doc/html/rfc9076)|July 2021|DNS Privacy Considerations|Docs todo|TODO|
|[RFC-9018](https://datatracker.ietf.org/doc/html/rfc9018)|April 2021|Interoperable Domain Name System (DNS) Server Cookies|Docs todo|TODO|
|[RFC-8976](https://datatracker.ietf.org/doc/html/rfc8976)|February 2021|Message Digest for DNS Zones|Docs todo|TODO|
|[RFC-8945](https://datatracker.ietf.org/doc/html/rfc8945)|November 2020|Secret Key Transaction Authentication for DNS (TSIG)|Docs todo|TODO|
|[RFC-8932](https://datatracker.ietf.org/doc/html/rfc8932)|October 2020|Recommendations for DNS Privacy Service Operators|Docs todo|TODO|
|[RFC-8914](https://datatracker.ietf.org/doc/html/rfc8914)|October 2020|Extended DNS Errors|Docs todo|TODO|
|[RFC-8906](https://datatracker.ietf.org/doc/html/rfc8906)|September 2020|A Common Operational Problem in DNS Servers: Failure to Communicate|Docs todo|TODO|
|[RFC-8901](https://datatracker.ietf.org/doc/html/rfc8901)|September 2020|Multi-Signer DNSSEC Models|Docs todo|TODO|
|[RFC-8882](https://datatracker.ietf.org/doc/html/rfc8882)|September 2020|DNS-Based Service Discovery (DNS-SD) Privacy and Security Requirements|Docs todo|TODO|
|[RFC-8880](https://datatracker.ietf.org/doc/html/rfc8880)|August 2020|Special Use Domain Name 'ipv4only.arpa'|Docs todo|TODO|
|[RFC-8806](https://datatracker.ietf.org/doc/html/rfc8806)|June 2020|Running a Root Server Local to a Resolver|Docs todo|TODO|
|[RFC-8777](https://datatracker.ietf.org/doc/html/rfc8777)|April 2020|DNS Reverse IP Automatic Multicast Tunneling (AMT) Discovery|Docs todo|TODO|
|[RFC-8767](https://datatracker.ietf.org/doc/html/rfc8767)|March 2020|Serving Stale Data to Improve DNS Resiliency|Docs todo|TODO|
|[RFC-8749](https://datatracker.ietf.org/doc/html/rfc8749)|March 2020|Moving DNSSEC Lookaside Validation (DLV) to Historic Status|Docs todo|TODO|
|[RFC-8659](https://datatracker.ietf.org/doc/html/rfc8659)|November 2019|DNS Certification Authority Authorization (CAA) Resource Record|Docs todo|TODO|
|[RFC-8624](https://datatracker.ietf.org/doc/html/rfc8624)|June 2019|Algorithm Implementation Requirements and Usage Guidance for DNSSEC|Docs todo|TODO|
|[RFC-8618](https://datatracker.ietf.org/doc/html/rfc8618)|September 2019|Compacted-DNS (C-DNS): A Format for DNS Packet Capture|Docs todo|TODO|
|[RFC-8598](https://datatracker.ietf.org/doc/html/rfc8598)|May 2019|Split DNS Configuration for the Internet Key Exchange Protocol Version 2 (IKEv2)|Docs todo|TODO|
|[RFC-8567](https://datatracker.ietf.org/doc/html/rfc8567)|April 2019|Customer Management DNS Resource Records|Docs todo|TODO|
|[RFC-8553](https://datatracker.ietf.org/doc/html/rfc8553)|March 2019|DNS Attrleaf Changes: Fixing Specifications That Use Underscored Node Names|Docs todo|TODO|
|[RFC-8552](https://datatracker.ietf.org/doc/html/rfc8552)|March 2019|Scoped Interpretation of DNS Resource Records through "Underscored" Naming of Attribute Leaves|Docs todo|TODO|
|[RFC-8509](https://datatracker.ietf.org/doc/html/rfc8509)|December 2018|A Root Key Trust Anchor Sentinel for DNSSEC|Docs todo|TODO|
|[RFC-8501](https://datatracker.ietf.org/doc/html/rfc8501)|November 2018|Reverse DNS in IPv6 for Internet Service Providers|Docs todo|TODO|
|[RFC-8499](https://datatracker.ietf.org/doc/html/rfc8499)|January 2019|DNS Terminology|Docs todo|TODO|
|[RFC-8490](https://datatracker.ietf.org/doc/html/rfc8490)|March 2019|DNS Stateful Operations|Docs todo|TODO|
|[RFC-8484](https://datatracker.ietf.org/doc/html/rfc8484)|October 2018|DNS Queries over HTTPS (DoH)|Docs todo|TODO|
|[RFC-8483](https://datatracker.ietf.org/doc/html/rfc8483)|October 2018|Yeti DNS Testbed|Docs todo|TODO|
|[RFC-8482](https://datatracker.ietf.org/doc/html/rfc8482)|January 2019|Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY|Docs todo|TODO|
|[RFC-8467](https://datatracker.ietf.org/doc/html/rfc8467)|October 2018|Padding Policies for Extension Mechanisms for DNS (EDNS(0))|Docs todo|TODO|
|[RFC-8427](https://datatracker.ietf.org/doc/html/rfc8427)|July 2018|Representing DNS Messages in JSON|Docs todo|TODO|
|[RFC-8375](https://datatracker.ietf.org/doc/html/rfc8375)|May 2018|Special-Use Domain 'home.arpa.'|Docs todo|TODO|
|[RFC-8324](https://datatracker.ietf.org/doc/html/rfc8324)|February 2018|DNS Privacy, Authorization, Special Uses, Encoding, Characters, Matching, and Root Structure: Time for Another Look?|Docs todo|TODO|
|[RFC-8310](https://datatracker.ietf.org/doc/html/rfc8310)|March 2018|Usage Profiles for DNS over TLS and DNS over DTLS|Docs todo|TODO|
|[RFC-8222](https://datatracker.ietf.org/doc/html/rfc8222)|September 2017|Selecting Labels for Use with Conventional DNS and Other Resolution Systems in DNS-Based Service Discovery|Docs todo|TODO|
|[RFC-8198](https://datatracker.ietf.org/doc/html/rfc8198)|July 2017|Aggressive Use of DNSSEC-Validated Cache|Docs todo|TODO|
|[RFC-8162](https://datatracker.ietf.org/doc/html/rfc8162)|May 2017|Using Secure DNS to Associate Certificates with Domain Names for S/MIME|Docs todo|TODO|
|[RFC-8145](https://datatracker.ietf.org/doc/html/rfc8145)|April 2017|Signaling Trust Anchor Knowledge in DNS Security Extensions (DNSSEC)|Docs todo|TODO|
|[RFC-8109](https://datatracker.ietf.org/doc/html/rfc8109)|March 2017|Initializing a DNS Resolver with Priming Queries|Docs todo|TODO|
|[RFC-8106](https://datatracker.ietf.org/doc/html/rfc8106)|March 2017|IPv6 Router Advertisement Options for DNS Configuration|Docs todo|TODO|
|[RFC-8094](https://datatracker.ietf.org/doc/html/rfc8094)|February 2017|DNS over Datagram Transport Layer Security (DTLS)|Docs todo|TODO|
|[RFC-8080](https://datatracker.ietf.org/doc/html/rfc8080)|February 2017|Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC|Docs todo|TODO|
|[RFC-8078](https://datatracker.ietf.org/doc/html/rfc8078)|March 2017|Managing DS Records from the Parent via CDS/CDNSKEY|Docs todo|TODO|
|[RFC-8027](https://datatracker.ietf.org/doc/html/rfc8027)|November 2016|DNSSEC Roadblock Avoidance|Docs todo|TODO|
|[RFC-8020](https://datatracker.ietf.org/doc/html/rfc8020)|November 2016|NXDOMAIN: There Really Is Nothing Underneath|Docs todo|TODO|
|[RFC-8005](https://datatracker.ietf.org/doc/html/rfc8005)|October 2016|Host Identity Protocol (HIP) Domain Name System (DNS) Extension|Docs todo|TODO|
|[RFC-7958](https://datatracker.ietf.org/doc/html/rfc7958)|August 2016|DNSSEC Trust Anchor Publication for the Root Zone|Docs todo|TODO|
|[RFC-7929](https://datatracker.ietf.org/doc/html/rfc7929)|August 2016|DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP|Docs todo|TODO|
|[RFC-7901](https://datatracker.ietf.org/doc/html/rfc7901)|June 2016|CHAIN Query Requests in DNS|Docs todo|TODO|
|[RFC-7873](https://datatracker.ietf.org/doc/html/rfc7873)|May 2016|Domain Name System (DNS) Cookies|Docs todo|TODO|
|[RFC-7871](https://datatracker.ietf.org/doc/html/rfc7871)|May 2016|Client Subnet in DNS Queries|Docs todo|TODO|
|[RFC-7858](https://datatracker.ietf.org/doc/html/rfc7858)|May 2016|Specification for DNS over Transport Layer Security (TLS)|Docs todo|TODO|
|[RFC-7830](https://datatracker.ietf.org/doc/html/rfc7830)|May 2016|The EDNS(0) Padding Option|Docs todo|TODO|
|[RFC-7828](https://datatracker.ietf.org/doc/html/rfc7828)|April 2016|The edns-tcp-keepalive EDNS0 Option|Docs todo|TODO|
|[RFC-7816](https://datatracker.ietf.org/doc/html/rfc7816)|March 2016|DNS Query Name Minimisation to Improve Privacy|Docs todo|TODO|
|[RFC-7793](https://datatracker.ietf.org/doc/html/rfc7793)|May 2016|Adding 100.64.0.0/10 Prefixes to the IPv4 Locally-Served DNS Zones Registry|Docs todo|TODO|
|[RFC-7766](https://datatracker.ietf.org/doc/html/rfc7766)|March 2016|DNS Transport over TCP - Implementation Requirements|Docs todo|TODO|
|[RFC-7745](https://datatracker.ietf.org/doc/html/rfc7745)|January 2016|XML Schemas for Reverse DNS Management|Docs todo|TODO|
|[RFC-7720](https://datatracker.ietf.org/doc/html/rfc7720)|December 2015|DNS Root Name Service Protocol and Deployment Requirements|Docs todo|TODO|
|[RFC-7719](https://datatracker.ietf.org/doc/html/rfc7719)|December 2015|DNS Terminology|Docs todo|TODO|
|[RFC-7673](https://datatracker.ietf.org/doc/html/rfc7673)|October 2015|Using DNS-Based Authentication of Named Entities (DANE) TLSA Records with SRV Records|Docs todo|TODO|
|[RFC-7671](https://datatracker.ietf.org/doc/html/rfc7671)|October 2015|The DNS-Based Authentication of Named Entities (DANE) Protocol: Updates and Operational Guidance|Docs todo|TODO|
|[RFC-7646](https://datatracker.ietf.org/doc/html/rfc7646)|September 2015|Definition and Use of DNSSEC Negative Trust Anchors|Docs todo|TODO|
|[RFC-7583](https://datatracker.ietf.org/doc/html/rfc7583)|October 2015|DNSSEC Key Rollover Timing Considerations|Docs todo|TODO|
|[RFC-7558](https://datatracker.ietf.org/doc/html/rfc7558)|July 2015|Requirements for Scalable DNS-Based Service Discovery (DNS-SD) / Multicast DNS (mDNS) Extensions|Docs todo|TODO|
|[RFC-7553](https://datatracker.ietf.org/doc/html/rfc7553)|June 2015|The Uniform Resource Identifier (URI) DNS Resource Record|Docs todo|TODO|
|[RFC-7535](https://datatracker.ietf.org/doc/html/rfc7535)|May 2015|AS112 Redirection Using DNAME|Docs todo|TODO|
|[RFC-7534](https://datatracker.ietf.org/doc/html/rfc7534)|May 2015|AS112 Nameserver Operations|Docs todo|TODO|
|[RFC-7479](https://datatracker.ietf.org/doc/html/rfc7479)|March 2015|Using Ed25519 in SSHFP Resource Records|Docs todo|TODO|
|[RFC-7477](https://datatracker.ietf.org/doc/html/rfc7477)|March 2015|Child-to-Parent Synchronization in DNS|Docs todo|TODO|
|[RFC-7393](https://datatracker.ietf.org/doc/html/rfc7393)|November 2014|Using the Port Control Protocol (PCP) to Update Dynamic DNS|Docs todo|TODO|
|[RFC-7344](https://datatracker.ietf.org/doc/html/rfc7344)|September 2014|Automating DNSSEC Delegation Trust Maintenance|Docs todo|TODO|
|[RFC-7314](https://datatracker.ietf.org/doc/html/rfc7314)|July 2014|Extension Mechanisms for DNS (EDNS) EXPIRE Option|Docs todo|TODO|
|[RFC-7304](https://datatracker.ietf.org/doc/html/rfc7304)|July 2014|A Method for Mitigating Namespace Collisions|Docs todo|TODO|
|[RFC-7218](https://datatracker.ietf.org/doc/html/rfc7218)|April 2014|Adding Acronyms to Simplify Conversations about DNS-Based Authentication of Named Entities (DANE)|Docs todo|TODO|
|[RFC-7129](https://datatracker.ietf.org/doc/html/rfc7129)|February 2014|Authenticated Denial of Existence in the DNS|Docs todo|TODO|
|[RFC-7108](https://datatracker.ietf.org/doc/html/rfc7108)|January 2014|A Summary of Various Mechanisms Deployed at L-Root for the Identification of Anycast Nodes|Docs todo|TODO|
|[RFC-7085](https://datatracker.ietf.org/doc/html/rfc7085)|December 2013|Top-Level Domains That Are Already Dotless|Docs todo|TODO|
|[RFC-7043](https://datatracker.ietf.org/doc/html/rfc7043)|October 2013|Resource Records for EUI-48 and EUI-64 Addresses in the DNS|Docs todo|TODO|
|[RFC-6975](https://datatracker.ietf.org/doc/html/rfc6975)|July 2013|Signaling Cryptographic Algorithm Understanding in DNS Security Extensions (DNSSEC)|Docs todo|TODO|
|[RFC-6950](https://datatracker.ietf.org/doc/html/rfc6950)|October 2013|Architectural Considerations on Application Features in the DNS|Docs todo|TODO|
|[RFC-6927](https://datatracker.ietf.org/doc/html/rfc6927)|May 2013|Variants in Second-Level Names Registered in Top-Level Domains|Docs todo|TODO|
|[RFC-6912](https://datatracker.ietf.org/doc/html/rfc6912)|April 2013|Principles for Unicode Code Point Inclusion in Labels in the DNS|Docs todo|TODO|
|[RFC-6895](https://datatracker.ietf.org/doc/html/rfc6895)|April 2013|Domain Name System (DNS) IANA Considerations|Docs todo|TODO|
|[RFC-6891](https://datatracker.ietf.org/doc/html/rfc6891)|April 2013|Extension Mechanisms for DNS (EDNS(0))|Docs todo|TODO|
|[RFC-6841](https://datatracker.ietf.org/doc/html/rfc6841)|January 2013|A Framework for DNSSEC Policies and DNSSEC Practice Statements|Docs todo|TODO|
|[RFC-6840](https://datatracker.ietf.org/doc/html/rfc6840)|February 2013|Clarifications and Implementation Notes for DNS Security (DNSSEC)|Docs todo|TODO|
|[RFC-6804](https://datatracker.ietf.org/doc/html/rfc6804)|November 2012|Supporting Multicast DNS Queries|Docs todo|TODO|
|[RFC-6781](https://datatracker.ietf.org/doc/html/rfc6781)|December 2012|DNSSEC Operational Practices, Version 2|Docs todo|TODO|
|[RFC-6763](https://datatracker.ietf.org/doc/html/rfc6763)|February 2013|DNS-Based Service Discovery|Docs todo|TODO|
|[RFC-6762](https://datatracker.ietf.org/doc/html/rfc6762)|February 2013|Multicast DNS|Docs todo|TODO|
|[RFC-6742](https://datatracker.ietf.org/doc/html/rfc6742)|November 2012|DNS Resource Records for the Identifier-Locator Network Protocol (ILNP)|Docs todo|TODO|
|[RFC-6731](https://datatracker.ietf.org/doc/html/rfc6731)|December 2012|Improved Recursive DNS Server Selection for Multi-Interfaced Nodes|Docs todo|TODO|
|[RFC-6725](https://datatracker.ietf.org/doc/html/rfc6725)|August  2012|DNS Security (DNSSEC) DNSKEY Algorithm IANA Registry Updates|Docs todo|TODO|
|[RFC-6698](https://datatracker.ietf.org/doc/html/rfc6698)|August 2012|The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA|Docs todo|TODO|
|[RFC-6672](https://datatracker.ietf.org/doc/html/rfc6672)|June 2012|DNAME Redirection in the DNS|Docs todo|TODO|
|[RFC-6641](https://datatracker.ietf.org/doc/html/rfc6641)|June 2012|Using DNS SRV to Specify a Global File Namespace with NFS Version 4|Docs todo|TODO|
|[RFC-6605](https://datatracker.ietf.org/doc/html/rfc6605)|April 2012|Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC|Docs todo|TODO|
|[RFC-6604](https://datatracker.ietf.org/doc/html/rfc6604)|April 2012|xNAME RCODE and Status Bits Clarification|Docs todo|TODO|
|[RFC-6594](https://datatracker.ietf.org/doc/html/rfc6594)|April 2012|Use of the SHA-256 Algorithm with RSA, Digital Signature Algorithm (DSA), and Elliptic Curve DSA (ECDSA) in SSHFP Resource Records|Docs todo|TODO|
|[RFC-6563](https://datatracker.ietf.org/doc/html/rfc6563)|March 2012|Moving A6 to Historic Status|Docs todo|TODO|
|[RFC-6471](https://datatracker.ietf.org/doc/html/rfc6471)|January 2012|Overview of Best Email DNS-Based List (DNSBL) Operational Practices|Docs todo|TODO|
|[RFC-6452](https://datatracker.ietf.org/doc/html/rfc6452)|November 2011|The Unicode Code Points and Internationalized Domain Names for Applications (IDNA) - Unicode 6.0|Docs todo|TODO|
|[RFC-6394](https://datatracker.ietf.org/doc/html/rfc6394)|October 2011|Use Cases and Requirements for DNS-Based Authentication of Named Entities (DANE)|Docs todo|TODO|
|[RFC-6303](https://datatracker.ietf.org/doc/html/rfc6303)|July 2011|Locally Served DNS Zones|Docs todo|TODO|
|[RFC-6186](https://datatracker.ietf.org/doc/html/rfc6186)|March 2011|Use of SRV Records for Locating Email Submission/Access Services|Docs todo|TODO|
|[RFC-6168](https://datatracker.ietf.org/doc/html/rfc6168)|May 2011|Requirements for Management of Name Servers for the DNS|Docs todo|TODO|
|[RFC-6147](https://datatracker.ietf.org/doc/html/rfc6147)|April 2011|DNS64: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers|Docs todo|TODO|
|[RFC-6118](https://datatracker.ietf.org/doc/html/rfc6118)|March 2011|Update of Legacy IANA Registrations of Enumservices|Docs todo|TODO|
|[RFC-6117](https://datatracker.ietf.org/doc/html/rfc6117)|March 2011|IANA Registration of Enumservices: Guide, Template, and IANA Considerations|Docs todo|TODO|
|[RFC-6116](https://datatracker.ietf.org/doc/html/rfc6116)|March 2011|The E.164 to Uniform Resource Identifiers (URI) Dynamic Delegation Discovery System (DDDS) Application (ENUM)|Docs todo|TODO|
|[RFC-6055](https://datatracker.ietf.org/doc/html/rfc6055)|February 2011|IAB Thoughts on Encodings for Internationalized Domain Names|Docs todo|TODO|
|[RFC-6014](https://datatracker.ietf.org/doc/html/rfc6014)|November 2010|Cryptographic Algorithm Identifier Allocation for DNSSEC|Docs todo|TODO|
|[RFC-5992](https://datatracker.ietf.org/doc/html/rfc5992)|October 2010|Internationalized Domain Names Registration and Administration Guidelines for European Languages Using Cyrillic|Docs todo|TODO|
|[RFC-5936](https://datatracker.ietf.org/doc/html/rfc5936)|June 2010|DNS Zone Transfer Protocol (AXFR)|Docs todo|TODO|
|[RFC-5933](https://datatracker.ietf.org/doc/html/rfc5933)|July 2010|Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC|Docs todo|TODO|
|[RFC-5910](https://datatracker.ietf.org/doc/html/rfc5910)|May 2010|Domain Name System (DNS) Security Extensions Mapping for the Extensible Provisioning Protocol (EPP)|Docs todo|TODO|
|[RFC-5895](https://datatracker.ietf.org/doc/html/rfc5895)|September 2010|Mapping Characters for Internationalized Domain Names in Applications (IDNA) 2008|Docs todo|TODO|
|[RFC-5894](https://datatracker.ietf.org/doc/html/rfc5894)|August 2010|Internationalized Domain Names for Applications (IDNA): Background, Explanation, and Rationale|Docs todo|TODO|
|[RFC-5893](https://datatracker.ietf.org/doc/html/rfc5893)|August 2010|Right-to-Left Scripts for Internationalized Domain Names for Applications (IDNA)|Docs todo|TODO|
|[RFC-5892](https://datatracker.ietf.org/doc/html/rfc5892)|August 2010|The Unicode Code Points and Internationalized Domain Names for Applications (IDNA)|Docs todo|TODO|
|[RFC-5891](https://datatracker.ietf.org/doc/html/rfc5891)|August 2010|Internationalized Domain Names in Applications (IDNA): Protocol|Docs todo|TODO|
|[RFC-5890](https://datatracker.ietf.org/doc/html/rfc5890)|August 2010|Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework|Docs todo|TODO|
|[RFC-5864](https://datatracker.ietf.org/doc/html/rfc5864)|April 2010|DNS SRV Resource Records for AFS|Docs todo|TODO|
|[RFC-5855](https://datatracker.ietf.org/doc/html/rfc5855)|May 2010|Nameservers for IPv4 and IPv6 Reverse Zones|Docs todo|TODO|
|[RFC-5782](https://datatracker.ietf.org/doc/html/rfc5782)|February 2010|DNS Blacklists and Whitelists|Docs todo|TODO|
|[RFC-5731](https://datatracker.ietf.org/doc/html/rfc5731)|August 2009|Extensible Provisioning Protocol (EPP) Domain Name Mapping|Docs todo|TODO|
|[RFC-5702](https://datatracker.ietf.org/doc/html/rfc5702)|October 2009|Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC|Docs todo|TODO|
|[RFC-5679](https://datatracker.ietf.org/doc/html/rfc5679)|December 2009|Locating IEEE 802.21 Mobility Services Using DNS|Docs todo|TODO|
|[RFC-5625](https://datatracker.ietf.org/doc/html/rfc5625)|August 2009|DNS Proxy Implementation Guidelines|Docs todo|TODO|
|[RFC-5564](https://datatracker.ietf.org/doc/html/rfc5564)|February 2010|Linguistic Guidelines for the Use of the Arabic Language in Internet Domains|Docs todo|TODO|
|[RFC-5526](https://datatracker.ietf.org/doc/html/rfc5526)|April 2009|The E.164 to Uniform Resource Identifiers (URI) Dynamic Delegation Discovery System (DDDS) Application for Infrastructure ENUM|Docs todo|TODO|
|[RFC-5507](https://datatracker.ietf.org/doc/html/rfc5507)|April 2009|Design Choices When Expanding the DNS|Docs todo|TODO|
|[RFC-5452](https://datatracker.ietf.org/doc/html/rfc5452)|January 2009|Measures for Making DNS More Resilient against Forged Answers|Docs todo|TODO|
|[RFC-5358](https://datatracker.ietf.org/doc/html/rfc5358)|October 2008|Preventing Use of Recursive Nameservers in Reflector Attacks|Docs todo|TODO|
|[RFC-5158](https://datatracker.ietf.org/doc/html/rfc5158)|March 2008|6to4 Reverse DNS Delegation Specification|Docs todo|TODO|
|[RFC-5155](https://datatracker.ietf.org/doc/html/rfc5155)|March 2008|DNS Security (DNSSEC) Hashed Authenticated Denial of Existence|Docs todo|TODO|
|[RFC-5144](https://datatracker.ietf.org/doc/html/rfc5144)|February 2008|A Domain Availability Check (DCHK) Registry Type for the Internet Registry Information Service (IRIS)|Docs todo|TODO|
|[RFC-5076](https://datatracker.ietf.org/doc/html/rfc5076)|December 2007|ENUM Validation Information Mapping for the Extensible Provisioning Protocol|Docs todo|TODO|
|[RFC-5074](https://datatracker.ietf.org/doc/html/rfc5074)|November 2007|DNSSEC Lookaside Validation (DLV)|Docs todo|TODO|
|[RFC-5011](https://datatracker.ietf.org/doc/html/rfc5011)|September 2007|Automated Updates of DNS Security (DNSSEC) Trust Anchors|Docs todo|TODO|
|[RFC-5001](https://datatracker.ietf.org/doc/html/rfc5001)|August 2007|DNS Name Server Identifier (NSID) Option|Docs todo|TODO|
|[RFC-4986](https://datatracker.ietf.org/doc/html/rfc4986)|August 2007|Requirements Related to DNS Security (DNSSEC) Trust Anchor Rollover|Docs todo|TODO|
|[RFC-4956](https://datatracker.ietf.org/doc/html/rfc4956)|July 2007|DNS Security (DNSSEC) Opt-In|Docs todo|TODO|
|[RFC-4955](https://datatracker.ietf.org/doc/html/rfc4955)|July 2007|DNS Security (DNSSEC) Experiments|Docs todo|TODO|
|[RFC-4892](https://datatracker.ietf.org/doc/html/rfc4892)|June 2007|Requirements for a Mechanism Identifying a Name Server Instance|Docs todo|TODO|
|[RFC-4848](https://datatracker.ietf.org/doc/html/rfc4848)|April 2007|Domain-Based Application Service Location Using URIs and the Dynamic Delegation Discovery Service (DDDS)|Docs todo|TODO|
|[RFC-4713](https://datatracker.ietf.org/doc/html/rfc4713)|October 2006|Registration and Administration Recommendations for Chinese Domain Names|Docs todo|TODO|
|[RFC-4701](https://datatracker.ietf.org/doc/html/rfc4701)|October 2006|A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR)|Docs todo|TODO|
|[RFC-4698](https://datatracker.ietf.org/doc/html/rfc4698)|October 2006|An Address Registry (areg) Type for the Internet Registry Information Service|Docs todo|TODO|
|[RFC-4697](https://datatracker.ietf.org/doc/html/rfc4697)|October 2006|Observed DNS Resolution Misbehavior|Docs todo|TODO|
|[RFC-4690](https://datatracker.ietf.org/doc/html/rfc4690)|September 2006|Review and Recommendations for Internationalized Domain Names (IDNs)|Docs todo|TODO|
|[RFC-4592](https://datatracker.ietf.org/doc/html/rfc4592)|July 2006|The Role of Wildcards in the Domain Name System|Docs todo|TODO|
|[RFC-4509](https://datatracker.ietf.org/doc/html/rfc4509)|May 2006|Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs)|Docs todo|TODO|
|[RFC-4501](https://datatracker.ietf.org/doc/html/rfc4501)|May 2006|Domain Name System Uniform Resource Identifiers|Docs todo|TODO|
|[RFC-4472](https://datatracker.ietf.org/doc/html/rfc4472)|April 2006|Operational Considerations and Issues with IPv6 DNS|Docs todo|TODO|
|[RFC-4471](https://datatracker.ietf.org/doc/html/rfc4471)|September 2006|Derivation of DNS Name Predecessor and Successor|Docs todo|TODO|
|[RFC-4470](https://datatracker.ietf.org/doc/html/rfc4470)|April 2006|Minimally Covering NSEC Records and DNSSEC On-line Signing|Docs todo|TODO|
|[RFC-4431](https://datatracker.ietf.org/doc/html/rfc4431)|February 2006|The DNSSEC Lookaside Validation (DLV) DNS Resource Record|Docs todo|TODO|
|[RFC-4408](https://datatracker.ietf.org/doc/html/rfc4408)|April 2006|Sender Policy Framework (SPF) for Authorizing Use of Domains in E-Mail, Version 1 |Docs todo|TODO|
|[RFC-4398](https://datatracker.ietf.org/doc/html/rfc4398)|March 2006|Storing Certificates in the Domain Name System (DNS)|Docs todo|TODO|
|[RFC-4367](https://datatracker.ietf.org/doc/html/rfc4367)|February 2006|What's in a Name: False Assumptions about DNS Names|Docs todo|TODO|
|[RFC-4355](https://datatracker.ietf.org/doc/html/rfc4355)|January 2006|IANA Registration for Enumservices email, fax, mms, ems, and sms|Docs todo|TODO|
|[RFC-4343](https://datatracker.ietf.org/doc/html/rfc4343)|January 2006|Domain Name System (DNS) Case Insensitivity Clarification|Docs todo|TODO|
|[RFC-4339](https://datatracker.ietf.org/doc/html/rfc4339)|February 2006|IPv6 Host Configuration of DNS Server Information Approaches|Docs todo|TODO|
|[RFC-4290](https://datatracker.ietf.org/doc/html/rfc4290)|December 2005|Suggested Practices for Registration of Internationalized Domain Names (IDN)|Docs todo|TODO|
|[RFC-4255](https://datatracker.ietf.org/doc/html/rfc4255)|January 2006|Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints|Docs todo|TODO|
|[RFC-4185](https://datatracker.ietf.org/doc/html/rfc4185)|October 2005|National and Local Characters for DNS Top Level Domain (TLD) Names|Docs todo|TODO|
|[RFC-4183](https://datatracker.ietf.org/doc/html/rfc4183)|September 2005|A Suggested Scheme for DNS Resolution of Networks and Gateways|Docs todo|TODO|
|[RFC-4159](https://datatracker.ietf.org/doc/html/rfc4159)|August 2005|Deprecation of ip6.int|Docs todo|TODO|
|[RFC-4143](https://datatracker.ietf.org/doc/html/rfc4143)|November 2005|Facsimile Using Internet Mail (IFAX) Service of ENUM|Docs todo|TODO|
|[RFC-4114](https://datatracker.ietf.org/doc/html/rfc4114)|June 2005|E.164 Number Mapping for the Extensible Provisioning Protocol (EPP)|Docs todo|TODO|
|[RFC-4074](https://datatracker.ietf.org/doc/html/rfc4074)|May 2005|Common Misbehavior Against DNS Queries for IPv6 Addresses|Docs todo|TODO|
|[RFC-4035](https://datatracker.ietf.org/doc/html/rfc4035)|March 2005|Protocol Modifications for the DNS Security Extensions|Docs todo|TODO|
|[RFC-4034](https://datatracker.ietf.org/doc/html/rfc4034)|March 2005|Resource Records for the DNS Security Extensions|Docs todo|TODO|
|[RFC-4033](https://datatracker.ietf.org/doc/html/rfc4033)|March 2005|DNS Security Introduction and Requirements|Docs todo|TODO|
|[RFC-4027](https://datatracker.ietf.org/doc/html/rfc4027)|April 2005|Domain Name System Media Types|Docs todo|TODO|
|[RFC-4025](https://datatracker.ietf.org/doc/html/rfc4025)|March 2005|A Method for Storing IPsec Keying Material in DNS|Docs todo|TODO|
|[RFC-3982](https://datatracker.ietf.org/doc/html/rfc3982)|January 2005|IRIS: A Domain Registry (dreg) Type for the Internet Registry Information Service (IRIS)|Docs todo|TODO|
|[RFC-3958](https://datatracker.ietf.org/doc/html/rfc3958)|January 2005|Domain-Based Application Service Location Using SRV RRs and the Dynamic Delegation Discovery Service (DDDS)|Docs todo|TODO|
|[RFC-3915](https://datatracker.ietf.org/doc/html/rfc3915)|September 2004|Domain Registry Grace Period Mapping for the Extensible Provisioning Protocol (EPP)|Docs todo|TODO|
|[RFC-3901](https://datatracker.ietf.org/doc/html/rfc3901)|September 2004|DNS IPv6 Transport Operational Guidelines|Docs todo|TODO|
|[RFC-3845](https://datatracker.ietf.org/doc/html/rfc3833)|?|?|-|no (obsoleted)|
|[RFC-3833](https://datatracker.ietf.org/doc/html/rfc3833)|August 2004|Threat Analysis of the Domain Name System (DNS)|Docs todo|TODO|
|[RFC-3832](https://datatracker.ietf.org/doc/html/rfc3832)|July 2004|Remote Service Discovery in the Service Location Protocol (SLP) via DNS SRV|Docs todo|TODO|
|[RFC-3757](https://datatracker.ietf.org/doc/html/rfc3757)|?|?|-|no (obsolete)|
|[RFC-3755](https://datatracker.ietf.org/doc/html/rfc3755)|?|?|-|no (obsolete)|
|[RFC-3743](https://datatracker.ietf.org/doc/html/rfc3743)|April 2004|Joint Engineering Team (JET) Guidelines for Internationalized Domain Names (IDN) Registration and Administration for Chinese, Japanese, and Korean|Docs todo|TODO|
|[RFC-3707](https://datatracker.ietf.org/doc/html/rfc3707)|February 2004|Cross Registry Internet Service Protocol (CRISP) Requirements|Docs todo|TODO|
|[RFC-3696](https://datatracker.ietf.org/doc/html/rfc3696)|February 2004|Application Techniques for Checking and Transformation of Names|Docs todo|TODO|
|[RFC-3681](https://datatracker.ietf.org/doc/html/rfc3681)|January 2004|Delegation of E.F.F.3.IP6.ARPA|Docs todo|TODO|
|[RFC-3675](https://datatracker.ietf.org/doc/html/rfc3675)|February 2004|.sex Considered Dangerous|Docs todo|TODO|
|[RFC-3665](https://datatracker.ietf.org/doc/html/rfc3665)|?|?|-|no obsolete|
|[RFC-3663](https://datatracker.ietf.org/doc/html/rfc3663)|December 2003|Domain Administrative Data in Lightweight Directory Access Protocol (LDAP)|Docs todo|TODO|
|[RFC-3658](https://datatracker.ietf.org/doc/html/rfc3658)|?|?|-|no obsolete|
|[RFC-3646](https://datatracker.ietf.org/doc/html/rfc3646)|December 2003|DNS Configuration options for Dynamic Host Configuration Protocol for IPv6 (DHCPv6)|Docs todo|TODO|
|[RFC-3645](https://datatracker.ietf.org/doc/html/rfc3645)|October 2003|Generic Security Service Algorithm for Secret Key Transaction Authentication for DNS (GSS-TSIG)|Docs todo|TODO|
|[RFC-3632](https://datatracker.ietf.org/doc/html/rfc3632)|November 2003|VeriSign Registry Registrar Protocol (RRP) Version 2.0.0|Docs todo|TODO|
|[RFC-3597](https://datatracker.ietf.org/doc/html/rfc3597)|September 2003|Handling of Unknown DNS Resource Record (RR) Types|Docs todo|TODO|
|[RFC-3596](https://datatracker.ietf.org/doc/html/rfc3596)|October 2003|DNS Extensions to Support IP Version 6|Docs todo|TODO|
|[RFC-3492](https://datatracker.ietf.org/doc/html/rfc3492)|March 2003|Punycode: A Bootstring encoding of Unicode for Internationalized Domain Names in Applications (IDNA)|Docs todo|TODO|
|[RFC-3467](https://datatracker.ietf.org/doc/html/rfc3467)|February 2003|Role of the Domain Name System (DNS)|Docs todo|TODO|
|[RFC-3445](https://datatracker.ietf.org/doc/html/rfc3445)|?|?|-|no obsolete|
|[RFC-3425](https://datatracker.ietf.org/doc/html/rfc3425)|November 2002|Obsoleting IQUERY|Docs todo|TODO|
|[RFC-3405](https://datatracker.ietf.org/doc/html/rfc3405)|October 2002|Dynamic Delegation Discovery System (DDDS) Part Five: URI.ARPA Assignment Procedures|Docs todo|TODO|
|[RFC-3404](https://datatracker.ietf.org/doc/html/rfc3404)|October 2002|Dynamic Delegation Discovery System (DDDS) Part Four: The Uniform Resource Identifiers (URI)|Docs todo|TODO|
|[RFC-3403](https://datatracker.ietf.org/doc/html/rfc3403)|October 2002|Dynamic Delegation Discovery System (DDDS) Part Three: The Domain Name System (DNS) Database|Docs todo|TODO|
|[RFC-3402](https://datatracker.ietf.org/doc/html/rfc3402)|October 2002|Dynamic Delegation Discovery System (DDDS) Part Two: The Algorithm|Docs todo|TODO|
|[RFC-3401](https://datatracker.ietf.org/doc/html/rfc3401)|October 2002|Dynamic Delegation Discovery System (DDDS) Part One: The Comprehensive DDDS|Docs todo|TODO|
|[RFC-3397](https://datatracker.ietf.org/doc/html/rfc3397)|November 2002|Dynamic Host Configuration Protocol (DHCP) Domain Search Option|Docs todo|TODO|
|[RFC-3375](https://datatracker.ietf.org/doc/html/rfc3375)|September 2002|Generic Registry-Registrar Protocol Requirements|Docs todo|TODO|
|[RFC-3364](https://datatracker.ietf.org/doc/html/rfc3364)|August 2002|Tradeoffs in Domain Name System (DNS) Support for Internet Protocol version 6 (IPv6)|Docs todo|TODO|
|[RFC-3363](https://datatracker.ietf.org/doc/html/rfc3363)|August 2002|Representing Internet Protocol version 6 (IPv6) Addresses in the Domain Name System (DNS)|Docs todo|TODO|
|[RFC-3258](https://datatracker.ietf.org/doc/html/rfc3258)|April 2002|Distributing Authoritative Name Servers via Shared Unicast Addresses|Docs todo|TODO|
|[RFC-3226](https://datatracker.ietf.org/doc/html/rfc3226)|December 2001|DNSSEC and IPv6 A6 aware server/resolver message size requirements|Docs todo|TODO|
|[RFC-3225](https://datatracker.ietf.org/doc/html/rfc3225)|December 2001|Indicating Resolver Support of DNSSEC|Docs todo|TODO|
|[RFC-3197](https://datatracker.ietf.org/doc/html/rfc3197)|November 2001|Applicability Statement for DNS MIB Extensions|Docs todo|TODO|
|[RFC-3172](https://datatracker.ietf.org/doc/html/rfc3172)|September 2001|Management Guidelines & Operational Requirements for the Address and Routing Parameter Area Domain (arpa)|Docs todo|TODO|
|[RFC-3130](https://datatracker.ietf.org/doc/html/rfc3130)|June 2001|Notes from the State-Of-The-Technology: DNSSEC|Docs todo|TODO|
|[RFC-3123](https://datatracker.ietf.org/doc/html/rfc3123)|June 2001|A DNS RR Type for Lists of Address Prefixes (APL RR)|Docs todo|TODO|
|[RFC-3110](https://datatracker.ietf.org/doc/html/rfc3110)|May 2001|RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)|Docs todo|TODO|
|[RFC-3090](https://datatracker.ietf.org/doc/html/rfc3090)|?|?|-|no obsolete|
|[RFC-3071](https://datatracker.ietf.org/doc/html/rfc3071)|February 2001|Reflections on the DNS, RFC 1591, and Categories of Domains|Docs todo|TODO|
|[RFC-3026](https://datatracker.ietf.org/doc/html/rfc3026)|January 2001|Liaison to IETF/ISOC on ENUM|Docs todo|TODO|
|[RFC-3008](https://datatracker.ietf.org/doc/html/rfc3008)|?|?|-|no obsolete|
|[RFC-3007](https://datatracker.ietf.org/doc/html/rfc3007)|November 2000|Secure Domain Name System (DNS) Dynamic Update|Docs todo|TODO|
|[RFC-3008](https://datatracker.ietf.org/doc/html/rfc2929)|?|?|-|no (obsoleted by 5395)|
|[RFC-2931](https://datatracker.ietf.org/doc/html/rfc2931)|September 2000|DNS Request and Transaction Signatures ( SIG(0)s )|Docs todo|TODO|
|[RFC-2930](https://datatracker.ietf.org/doc/html/rfc2930)|September 2000|Secret Key Establishment for DNS (TKEY RR)|Docs todo|TODO|
|[RFC-2915](https://datatracker.ietf.org/doc/html/rfc2915)|September 2000|The Naming Authority Pointer (NAPTR) DNS Resource Record|Docs todo|TODO|
|[RFC-2874](https://datatracker.ietf.org/doc/html/rfc2874)|July 2000|DNS Extensions to Support IPv6 Address Aggregation and Renumbering|Docs todo|TODO|
|[RFC-2832](https://datatracker.ietf.org/doc/html/rfc2832)|May 2000|NSI Registry Registrar Protocol (RRP) Version 1.1.0|Docs todo|TODO|
|[RFC-2826](https://datatracker.ietf.org/doc/html/rfc2826)|May 2000|IAB Technical Comment on the Unique DNS Root|Docs todo|TODO|
|[RFC-2825](https://datatracker.ietf.org/doc/html/rfc2825)|May 2000|A Tangled Web: Issues of I18N, Domain Names, and the Other Internet protocols|Docs todo|TODO|
|[RFC-2782](https://datatracker.ietf.org/doc/html/rfc2782)|February 2000|A DNS RR for specifying the location of services (DNS SRV)|Docs todo|TODO|
|[RFC-2694](https://datatracker.ietf.org/doc/html/rfc2694)|September 1999|DNS extensions to Network Address Translators (DNS_ALG)|Docs todo|TODO|
|[RFC-2606](https://datatracker.ietf.org/doc/html/rfc2606)|June 1999|Reserved Top Level DNS Names|Docs todo|TODO|
|[RFC-2540](https://datatracker.ietf.org/doc/html/rfc2540)|March 1999|Detached Domain Name System (DNS) Information|Docs todo|TODO|
|[RFC-2539](https://datatracker.ietf.org/doc/html/rfc2539)|March 1999|Storage of Diffie-Hellman Keys in the Domain Name System (DNS)|Docs todo|TODO|
|[RFC-2536](https://datatracker.ietf.org/doc/html/rfc2536)|March 1999|DSA KEYs and SIGs in the Domain Name System (DNS)|Docs todo|TODO|
|[RFC-2535](https://datatracker.ietf.org/doc/html/rfc2535)|?|?|-|no obsolete|
|[RFC-2517](https://datatracker.ietf.org/doc/html/rfc2517)|February 1999|Building Directories from DNS: Experiences from WWWSeeker|Docs todo|TODO|
|[RFC-2352](https://datatracker.ietf.org/doc/html/rfc2352)|May 1998|A Convention For Using Legal Names as Domain Names|Docs todo|TODO|
|[RFC-2345](https://datatracker.ietf.org/doc/html/rfc2345)|May 1998|Domain Names and Company Name Retrieval|Docs todo|TODO|
|[RFC-2317](https://datatracker.ietf.org/doc/html/rfc2317)|March 1998|Classless IN-ADDR.ARPA delegation|Docs todo|TODO|
|[RFC-2308](https://datatracker.ietf.org/doc/html/rfc2308)|March 1998|Negative Caching of DNS Queries (DNS NCACHE)|Docs todo|TODO|
|[RFC-2230](https://datatracker.ietf.org/doc/html/rfc2230)|November 1997|Key Exchange Delegation Record for the DNS|Docs todo|TODO|
|[RFC-2219](https://datatracker.ietf.org/doc/html/rfc2219)|October 1997|Use of DNS Aliases for Network Services|Docs todo|TODO|
|[RFC-2182](https://datatracker.ietf.org/doc/html/rfc2182)|July 1997|Selection and Operation of Secondary DNS Servers|Docs todo|TODO|
|[RFC-2181](https://datatracker.ietf.org/doc/html/rfc2181)|July 1997|Clarifications to the DNS Specification|Docs todo|TODO|
|[RFC-2163](https://datatracker.ietf.org/doc/html/rfc2163)|January 1998|Using the Internet DNS to Distribute MIXER Conformant Global Address Mapping (MCGAM)|Docs todo|TODO|
|[RFC-2146](https://datatracker.ietf.org/doc/html/rfc2146)|May 1997|U.S. Government Internet Domain Names|Docs todo|TODO|
|[RFC-2136](https://datatracker.ietf.org/doc/html/rfc2136)|April 1997|Dynamic Updates in the Domain Name System (DNS UPDATE)|Docs todo|TODO|
|[RFC-2065](https://datatracker.ietf.org/doc/html/rfc2065)|?|?|-|no obsolete|
|[RFC-2053](https://datatracker.ietf.org/doc/html/rfc2053)|October 1996|The AM (Armenia) Domain|Docs todo|TODO|
|[RFC-1996](https://datatracker.ietf.org/doc/html/rfc1996)|August 1996|A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)|Docs todo|TODO|
|[RFC-1995](https://datatracker.ietf.org/doc/html/rfc1995)|August 1996|Incremental Zone Transfer in DNS|Docs todo|TODO|
|[RFC-1982](https://datatracker.ietf.org/doc/html/rfc1982)|August 1996|Serial Number Arithmetic|Docs todo|TODO|
|[RFC-1956](https://datatracker.ietf.org/doc/html/rfc1956)|June 1996|Registration in the MIL Domain|Docs todo|TODO|
|[RFC-1912](https://datatracker.ietf.org/doc/html/rfc1912)|February 1996|Common DNS Operational and Configuration Errors|Docs todo|TODO|
|[RFC-1876](https://datatracker.ietf.org/doc/html/rfc1876)|January 1996|A Means for Expressing Location Information in the Domain Name System|-|maybe (legacy)|
|[RFC-1794](https://datatracker.ietf.org/doc/html/rfc1794)|April 1995|DNS Support for Load Balancing|-|no (informational)|
|[RFC-1788](https://datatracker.ietf.org/doc/html/rfc1788)|April 1995|ICMP Domain Name Messages|-|no (legacy)|
|[RFC-1713](https://datatracker.ietf.org/doc/html/rfc1713)|November 1994|Tools for DNS debugging|-|no (legacy)|
|[RFC-1712](https://datatracker.ietf.org/doc/html/rfc1712)|November 1994|DNS Encoding of Geographical Location|-|maybe (legacy)|
|[RFC-1706](https://datatracker.ietf.org/doc/html/rfc1706)|October 1994|DNS NSAP Resource Records|-|no (legacy)|
|[RFC-1612](https://datatracker.ietf.org/doc/html/rfc1612)|May 1994|DNS Resolver MIB Extensions|-|no (historic)|
|[RFC-1611](https://datatracker.ietf.org/doc/html/rfc1611)|May 1994|DNS Server MIB Extensions|-|no (historic)|
|[RFC-1591](https://datatracker.ietf.org/doc/html/rfc1591)|March 1994|Domain Name System Structure and Delegation|-|no (legacy)|
|[RFC-1536](https://datatracker.ietf.org/doc/html/rfc1536)|October 1993|Common DNS Implementation Errors and Suggested Fixes|Docs todo|no (informational)|
|[RFC-1535](https://datatracker.ietf.org/doc/html/rfc1535)|October 1993|A Security Problem and Proposed Correction With Widely Deployed DNS Software|Docs todo|no (informational)|
|[RFC-1480](https://datatracker.ietf.org/doc/html/rfc1480)|June 1993|The US Domain|-|no (informational)|
|[RFC-1464](https://datatracker.ietf.org/doc/html/rfc1464)|May 1993|Using the Domain Name System To Store Arbitrary String Attributes|-|no (existing code do this)|
|[RFC-1401](https://datatracker.ietf.org/doc/html/rfc1401)|January 1993|Correspondence between the IAB and DISA on the use of DNS|-|no (informational)|
|[RFC-1394](https://datatracker.ietf.org/doc/html/rfc1394)|January 1993|Relationship of Telex Answerback Codes to Internet Domains|-|no (informational)|
|[RFC-1401](https://datatracker.ietf.org/doc/html/rfc1386)|-|-|-|no (obsoleted)|
|[RFC-1383](https://datatracker.ietf.org/doc/html/rfc1383)|December 1992|An Experiment in DNS Based IP Routing|-|no (experimental?)|
|[RFC-1279](https://datatracker.ietf.org/doc/html/rfc1279)|November 1991|X.500 and Domains|Docs todo|no (todo?)|
|[RFC-1183](https://datatracker.ietf.org/doc/html/rfc1183)|October 1990|New DNS RR Definitions|Docs todo|TODO (AFSDB todo)|
|[RFC-1101](https://datatracker.ietf.org/doc/html/rfc1101)|April 1989|DNS encoding of network names and other types|-|no (legacy)|
|[RFC-1035](https://datatracker.ietf.org/doc/html/rfc1035)|November 1987|Domain names - implementation and specification|Docs todo|yes|
|[RFC-1034](https://datatracker.ietf.org/doc/html/rfc1034)|November 1987|Domain names - concepts and facilities|Docs todo|yes|
|[RFC-1033](https://datatracker.ietf.org/doc/html/rfc1033)|November 1987|Domain Administrators Operations Guide|-|no (legacy)|
|[RFC-1032](https://datatracker.ietf.org/doc/html/rfc1032)|November 1987|Domain administrators guide|-|no (legacy)|
|[RFC-1031](https://datatracker.ietf.org/doc/html/rfc1031)|November 1987|MILNET name domain transition|-|no (legacy)|
|[RFC-0974](https://datatracker.ietf.org/doc/html/rfc0974)|January 1986|Mail routing and the domain system|-|no (legacy)|
|[RFC-0952](https://datatracker.ietf.org/doc/html/rfc0952)|October 1985|DoD Internet host table specification|-|no (legacy)|
|[RFC-0921](https://datatracker.ietf.org/doc/html/rfc0921)|October 1984|Domain name system implementation schedule|-|no (legacy)|
|[RFC-0920](https://datatracker.ietf.org/doc/html/rfc0920)|October 1984|Domain requirements|-|no (legacy)|
|[RFC-0897](https://datatracker.ietf.org/doc/html/rfc0897)|February 1984|Domain name system implementation schedule|-|no (legacy)|
|[RFC-0881](https://datatracker.ietf.org/doc/html/rfc0881)|November 1983|Domain names plan and schedule|-|no (legacy)|
|[RFC-0819](https://datatracker.ietf.org/doc/html/rfc0819)|August 1982|Domain naming convention for Internet user applications|-|no (legacy)|
|[RFC-0799](https://datatracker.ietf.org/doc/html/rfc0799)|September 1981|Internet name domains|-|no (legacy)|






## TLS 1.3
#### TLS 1.3 - Supported Features
|Name|Supported|Comment|
|:--:|:--:|:----:|
|Cipher suites (RFC 8446)| TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256|Supported Cipher suites|
|Named Groups (RFC 8446)|Secp256r1, Secp384r1, Secp521r1, X25519, X448, Ffdhe2048, Ffdhe3072, Ffdhe4096, Ffdhe6144, Ffdhe8192|Supported Groups - Configurable on Client/Server (e.g. can only use X25519 and not any other)|
|NewSessionTicket (RFC 8446)|Yes|Client & Server (Client accept ticket and can use it, server generates ticket and send to client, both configurable)|
|Signature Schemes (RFC 8446)| EcdsaSecp256r1Sha256, EcdsaSecp384r1Sha384, EcdsaSecp521r1Sha512, RsaPssRsaeSha256, RsaPssRsaeSha384, RsaPssRsaeSha512|Signature generation & validation|
|Key Update (RFC 8446)|Yes|On Client & Server. At any time server or client can send key update any number of time. Keys are updated|
|Handshake Client Authentication|Yes|Client & Server - client can authenticate and server can request (configurable)|
|Post handhsake client authentication|Yes|Client & Server configurable. Client can authenticate multiple times server can request authentication at any time after handshake|
|Multiple server certificates|Yes|Server can have multiple certificates and select them based on client hello supported features|
|Extension - Server Name (RFC 6066)|Yes| |
|Extension - PskKeyExchangeMode (RFC 8446)|Yes|Must support because TLS 1.3 specs require it|
|Extension - Application Layer Protocol Negotiation (RFC-7301)|Yes|On client & server. Client can send any bytes (defined by IANA or arbitrary bytes) and server can accept/reject any ALPN or ignore this extension|
|Extension - Supported Version (RFC 8446)|Yes|Must be required by TLS 1.3 spec|
|Extension - Cookie (RFC 8446))|Yes|Required by TLS 1.3 spec|
|Extension - Signature Algorithms (RFC 8446)|Yes|Client & Server, configurable|
|Extension - KeyShare (RFC 8446)|Yes|Required by TLS 1.3 spec|
|Extension - SupportedGroups|Yes||
|Extension - MaxFragmentLength (RFC 6066)|Yes|Configurable on client & server|
|Extension - OidFilters|Yes|Can send this extension but only as raw bytes (so DER encoded from external source, Arctium lib can't encode to DER bytes for now)|
|Extension - Signature Algorithms Cert|Yes|Client & server can sent this extension|
|Extension - Certificate Authorities|Yes|Configurable|
|Extension - GREASE (RFC 9701)|Yes|Client & Server Configurable - can be enabled or disabled|

To use Arctium TLS 1.3 examples below following file with sample resources must be included. Examples base on it. If not included code will not compite and will need to be changed.

[Examples - Resources][tls13-examples-resources]

[tls13-examples-resources]:<docs/lookup/tls13-examples-resources.md>

#### TLS 1.3 - Basic Example
|Name|Link|Comment|
|:--:|:--:|:--:|
|Client - Basic connection|[Example Code][tls13-basic-example-client]|Connect to www.github.com|
|Server - Basic server|[Example Code][tls13-basic-example-server]|HTTP response for browser (e.g. Edge)|
|Client - ConnectionInfo|[Example Code][tls13-basic-example-client-connectioninfo]|Client - Show informations about established TLS 1.3 connection|
|Server - ConnectionInfo|[Example Code][tls13-basic-example-server-connectioninfo]|Server - Show informations about established TLS 1.3 connection|
|Client/Server - Close Connection|[Example Code][tls13-basic-example-closeconnection]|Closing TLS 1.3 connection|
|Setup server and connect client|[Example Code][tls13-basic-example-self-client-server]|Connect Arctium TLS 1.3 client to Arctium TLS 1.3 Server|
|Client/Server - Update Traffic Secret|[Example Code][tls13-basic-example-updatetrafficsecret]|Update Traffic Secret|
Key and Initialization Vector Update

[tls13-basic-example-client]:<docs/lookup/tls13-basic-example-client.md>
[tls13-basic-example-server]:<docs/lookup/tls13-basic-example-server.md>
[tls13-basic-example-client-connectioninfo]:<docs/lookup/tls13-basic-example-client-connectioninfo.md>
[tls13-basic-example-server-connectioninfo]:<docs/lookup/tls13-basic-example-server-connectioninfo.md>
[tls13-basic-example-closeconnection]:<docs/lookup/tls13-basic-example-closeconnection.md>
[tls13-basic-example-self-client-server]:<docs/lookup/tls13-basic-example-self-client-server.md>
[tls13-basic-example-updatetrafficsecret]:<docs/lookup/tls13-basic-example-updatetrafficsecret.md>

#### Arctium TLS 1.3 - Expected Usage Example
|Name|Link|Comment|
|:--:|:--:|:--:|
|Search Browser|[Example Code][tls13-client-github-search]|Very simple Console App for searching www.github.com and showing results|
|HTTP Server|[Example Code][tls13-server-webserver]|Very simple Console App HTTP server that handle multiple TLS 1.3 connections parallel|

[tls13-client-github-search]:<docs/lookup/tls13-client-github-search.md>
[tls13-server-webserver]:<docs/lookup/tls13-server-webserver.md>

#### Tls 1.3 - Server Configuration
|Name|Link|Comment|
|:--:|:--:|:--:|
|Cipher Suites|[Example Code][tls13-serverconfig-ciphersuites]|How to use specific cipher suites|
|Extension - Supported Groups|[Example Code][tls13-serverconfig-extension-supportedgroups]|How to allow specific groups to be used in key exchange|
|Extension - Signature Schemes|[Example Code][tls13-serverconfig-extension-signatureschemes]|How to allow specific signature schemes to be used in signature generation|
|Extension - Record Size Limit|[Example Code][tls13-serverconfig-extension-recordsizelimit]|How to configure Record size limit extension|
|Extension - ALPN|[Example Code][tls13-serverconfig-extension-alpn]|How to configure ALPN extension|
|Extension - Server Name|[Example Code][tls13-serverconfig-servername]|How to configure server name extension|
|Handshake Client Authentication|[Example Code][tls13-serverconfig-handshakeclientauth]|How to request client authentication during TLS 1.3 handshake|
|Extension - Oid Filters|[Example Code][tls13-serverconfig-extension-oidfilters]|How to configure Oid Filters extension|
|Extension - Post Handshake Client Authentication|[Example Code][tls13-serverconfig-posthandshakeclientauth]|How to configure post handshake client authentication and request client to authenticated at any time after after handshake completed|
|Extension - Certificate Authorities|[Example Code][tls13-serverconfig-extension-certauthorities]|How to configure certificate authorities extension|
|Extension - Pre Shared Key|[Example Code][tls13-serverconfig-presharedkey]|How to configure Pre shared key|
|Extension - GREASE|[Example Code][tls13-serverconfig-grease]|How to enable/disable GREASE extension|

[tls13-serverconfig-ciphersuites]:<docs/lookup/tls13-serverconfig-ciphersuites.md>
[tls13-serverconfig-extension-supportedgroups]:<docs/lookup/tls13-serverconfig-extension-supportedgroups.md>
[tls13-serverconfig-extension-signatureschemes]:<docs/lookup/tls13-serverconfig-extension-signatureschemes.md>
[tls13-serverconfig-extension-recordsizelimit]:<docs/lookup/tls13-serverconfig-extension-recordsizelimit.md>
[tls13-serverconfig-extension-alpn]:<docs/lookup/tls13-serverconfig-extension-alpn.md>
[tls13-serverconfig-servername]:<docs/lookup/tls13-serverconfig-servername.md>
[tls13-serverconfig-handshakeclientauth]:<docs/lookup/tls13-serverconfig-handshakeclientauth.md>
[tls13-serverconfig-extension-oidfilters]:<docs/lookup/tls13-serverconfig-extension-oidfilters.md>
[tls13-serverconfig-posthandshakeclientauth]:<docs/lookup/tls13-serverconfig-posthandshakeclientauth.md>
[tls13-serverconfig-extension-certauthorities]:<docs/lookup/tls13-serverconfig-extension-certauthorities.md>
[tls13-serverconfig-presharedkey]:<docs/lookup/tls13-serverconfig-presharedkey.md>
[tls13-serverconfig-grease]:<docs/lookup/tls13-serverconfig-grease.md>



#### Tls 1.3 - Client Configuration
|Name|Link|Comment|
|:--:|:--:|:--:|
|Cipher Suites|[Example Code][tls13-clientconfig-ciphersuites]|How to use specific cipher suites|
|Extension - Supported Groups|[Example Code][tls13-clientconfig-supportedgroups]|How to allow specific groups to be used in key exchange|
|Extension - Key share|[Example Code][tls13-clientconfig-keyshare]|How to precompute and sent specific groups in client hello in keyshare|
|Extension - Supported Signature Scheme|[Example Code][tls13-clientconfig-supportedsignatureschemes]|How to allow specific signature schemes to be used in signing operation|
|Extension - Record Size Limit|[Example Code][tls13-clientconfig-recordsizelimit]|How to configure Record size limit|
|Extension - ALPN|[Example Code][tls13-clientconfig-alpn]|How to configure ALPN (Application layer protocol negotiation)|
|Extension - Server Name|[Example Code][tls13-clientconfig-servername]|How to configure Server Name extension|
|Extension - Signature Algorithms Cert|[Example Code][tls13-clientconfig-signaturealgorithmscert]|How to configure Signature Algorithms Cert extension|
|Handshake Client Authentication|[Example Code][tls13-clientconfig-handshakeclientauth]|How to configure Handshake Client Authentication|
|Post Handshake Client Authentication|[Example Code][tls13-clientconfig-posthandshakeclientauth]|How to configure Post Handshake Client Authentication (server can request at any time, multiple times supported even with different client x509 certificates for each auth request)|
|Extension - Certificate Authorities|[Example Code][tls13-clientconfig-certauthorities]|How to configure certificate authorities|
|Extension - Pre Shared Key|[Example Code][tls13-clientconfig-presharedkey]|How to configure Pre Shared Key|
|Extension - GREASE|[Example Code][tls13-clientconfig-grease]|How to configure GREASE extension|

[tls13-clientconfig-ciphersuites]:<docs/lookup/tls13-clientconfig-ciphersuites.md>
[tls13-clientconfig-supportedgroups]:<docs/lookup/tls13-clientconfig-supportedgroups.md>
[tls13-clientconfig-keyshare]:<docs/lookup/tls13-clientconfig-keyshare.md>
[tls13-clientconfig-supportedsignatureschemes]:<docs/lookup/tls13-clientconfig-supportedsignatureschemes.md>
[tls13-clientconfig-recordsizelimit]:<docs/lookup/tls13-clientconfig-recordsizelimit.md>
[tls13-clientconfig-alpn]:<docs/lookup/tls13-clientconfig-alpn.md>
[tls13-clientconfig-servername]:<docs/lookup/tls13-clientconfig-servername.md>
[tls13-clientconfig-signaturealgorithmscert]:<docs/lookup/tls13-clientconfig-signaturealgorithmscert.md>
[tls13-clientconfig-handshakeclientauth]:<docs/lookup/tls13-clientconfig-handshakeclientauth.md>
[tls13-clientconfig-posthandshakeclientauth]:<docs/lookup/tls13-clientconfig-posthandshakeclientauth.md>
[tls13-clientconfig-certauthorities]:<docs/lookup/tls13-clientconfig-certauthorities.md>
[tls13-clientconfig-presharedkey]:<docs/lookup/tls13-clientconfig-presharedkey.md>
[tls13-clientconfig-grease]:<docs/lookup/tls13-clientconfig-grease.md>

## Elliptic Curves - SEC 2 / Verify Signature
|Name|Link|Comment|
|:--:|:--:|:--:|
|secp192k1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp192r1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp224k1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp224r1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp256k1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp256r1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp384r1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp521r1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|


[sec2-versign]:<docs/lookup/sec2-versign.md>


## Elliptic Curves - SEC 2 / Generate Signature
|Name|Link|Comment|
|:--:|:--:|:--:|
|secp192k1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp192r1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp224k1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp224r1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp256k1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp256r1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp384r1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp521r1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|

[sec2-sign]:<docs/lookup/sec2-sign.md>


## Elliptic Curves - SEC 2 / Key Exchange
|Name|Link|Comment|
|:--:|:--:|:--:|
|secp192k1|[Example Code][sec2-keyex]|Key Exchange example|
|secp192r1|[Example Code][sec2-keyex]|Key Exchange example|
|secp224k1|[Example Code][sec2-keyex]|Key Exchange example|
|secp224r1|[Example Code][sec2-keyex]|Key Exchange example|
|secp256k1|[Example Code][sec2-keyex]|Key Exchange example|
|secp256r1|[Example Code][sec2-keyex]|Key Exchange example|
|secp384r1|[Example Code][sec2-keyex]|Key Exchange example|
|secp521r1|[Example Code][sec2-keyex]|Key Exchange example|

[sec2-keyex]:<docs/lookup/sec2-keyex.md>

Arbitrary curve (not predefined, parameters must be provided):
[Arbitrary curve code examples][ecc-arbitrary]

[ecc-arbitrary]:<docs/lookup/sec2-keyex.md>

## Stream Ciphers
|Name|Link|Comment|
|:--:|:--:|:--:|
|CHACHA-20|[Code Example][strciph-chacha20]|ChaCha-20 Stream Cipher|
|Rabbit|[Code Example][strciph-rabbit]|Rabbit Stream Cipher|
|HC-256|[Code Example][strciph-hc256]|HC-256 Stream Cipher|

[strciph-chacha20]:<docs/lookup/strciph-chacha20.md>
[strciph-rabbit]:<docs/lookup/strciph-rabbit.md>
[strciph-hc256]:<docs/lookup/strciph-hc256.md>

## Block Ciphers
|Name|Link|Comment|
|:--:|:--:|:--:|
|AES-128|[Code Example][blockciph-aes128]|AES 128 Block Cipher|
|AES-192|[Code Example][blockciph-aes192]|AES 192 Block Cipher|
|AES-512|[Code Example][blockciph-aes256]|AES 256 Block Cipher|
|Camellia|[Code Example][blockciph-camellia]|Camellia Block cipher|
|Threefish-256|[Code Example][blockciph-threefish256]|Threefish 256 Block cipher|
|Threefish-512|[Code Example][blockciph-threefish512]|Threefish 512 Block cipher|
|Threefish-1024|[Code Example][blockciph-threefish1024]|Threefish 1024 Block cipher|
|Twofish|[Code Example][blockciph-twofish]|Twofish Block cipher|

[blockciph-aes128]:<docs/lookup/blockciph-aes128.md>
[blockciph-aes192]:<docs/lookup/blockciph-aes192.md>
[blockciph-aes256]:<docs/lookup/blockciph-aes256.md>
[blockciph-camellia]:<docs/lookup/blockciph-camellia.md>
[blockciph-threefish1024]:<docs/lookup/blockciph-threefish1024.md>
[blockciph-threefish256]:<docs/lookup/blockciph-threefish256.md>
[blockciph-threefish512]:<docs/lookup/blockciph-threefish512.md>
[blockciph-twofish]:<docs/lookup/blockciph-twofish.md>

## AEAD
|Name|Link|Comment|
|:--:|:--:|:--:|
|Poly1305-Chacha20|[Example Code][aead-poly1305chacha20]||
|Galois Counter Mode|[Example Code][aead-gcm]|GCM mode with custom tag length|
|CCM Mode|[Example Code][aead-ccm]|Dont use not work / TODO|

[aead-gcm]:<docs/lookup/aead-gcm.md>
[aead-ccm]:<docs/lookup/aead-ccm.md>
[aead-poly1305chacha20]:<docs/lookup/aead-poly1305.md>

## AEAD Predefined (RFC-5116)
|Name|Link|Comment|
|:--:|:--:|:--:|
|AEAD AES 128 CCM|[Example Code][rfc5116-aes128ccm]|Dont Use - Not working TODO/ Create AEAD Algorithm AES 128 CCM|
|AEAD AES 256 GCM|[Example Code][rfc5116-aes256gcm]|Create AEAD Algorithm AES 256 GCM|
|AEAD AES 256 CCM|[Example Code][rfc5116-aes256ccm]|Dont Use - Not working TODO / Create AEAD Algorithm AES 256 CCM|
|AEAD AES 128 CCM 8|[Example Code][rfc5116-aes128ccm8]|Create AEAD Algorithm AES 128 CCM 8|

[rfc5116-aes128ccm]:<docs/lookup/rfc5116-aes128ccm.md>
[rfc5116-aes256gcm]:<docs/lookup/rfc5116-aes256gcm.md>
[rfc5116-aes256ccm]:<docs/lookup/rfc5116-aes256ccm.md>
[rfc5116-aes128ccm8]:<docs/lookup/rfc5116-aes128ccm8.md>

## X25519 & X448 (RFC 7748)
|Name|Link|Comment|
|:--:|:--:|:--:|
|X25519 Curve|[Example Code][rfc7748-x25519]|Key Exchange using X25519 Curve|
|X448 Curve|[Example Code][rfc7748-x448]|Key Exchange using X448 Curve|

[rfc7748-x25519]:<docs/lookup/rfc7748-x25519.md>
[rfc7748-x448]:<docs/lookup/rfc7748-x448.md>

## PKCS#8
|Name|Link|Comment|
|:--:|:--:|:--:|
|PKCS#8 - Decode RSA private key from PKCS#8 file|[Example Code][pkcs8-rsa]|How to decode RSA Private key from PKCS#8 file|
|PKCS#8 - Decode ECC private key from PKCS#8 file|[Example Code][pkcs8-ecc]|How to decode ECC Private key from PKCS#8 file|

[pkcs8-rsa]:<docs/lookup/pkcs8-rsa.md>
[pkcs8-ecc]:<docs/lookup/pkcs8-ecc.md>

## FFDHE - RFC-7919
|Name|Link|Comment|
|:--:|:--:|:--:|
|FFDHE2048|[Example Code][ffdherfc7919]|Key Exchange using FFDHE2048|
|FFDHE3072|[Example Code][ffdherfc7919]|Key Exchange using FFDHE3072|
|FFDHE4096|[Example Code][ffdherfc7919]|Key Exchange using FFDHE4096|
|FFDHE6144|[Example Code][ffdherfc7919]|Key Exchange using FFDHE6144|
|FFDHE8192|[Example Code][ffdherfc7919]|Key Exchange using FFDHE8192|


[ffdherfc7919]:<docs/lookup/ffdherfc7919.md>
[ffdherfc7919]:<docs/lookup/ffdherfc7919.md>
[ffdherfc7919]:<docs/lookup/ffdherfc7919.md>
[ffdherfc7919]:<docs/lookup/ffdherfc7919.md>
[ffdherfc7919]:<docs/lookup/ffdherfc7919.md>

## PEM file decoding
|Name|Link|Comment|
|:--:|:--:|:--:|
|PEM - from file|[Example Code][pem-fromfile]|Decode PEM file from file on file system|
|PEM - from string|[Example Code][pem-fromstring]|Decode PEM file from string|

[pem-fromstring]:<docs/lookup/pem-fromstring.md>
[pem-fromfile]:<docs/lookup/pem-fromfile.md>

## Hash Functions
|Name|Link|Comment|
|:--:|:--:|:--:|
|BLAKE2b|[Example Code][hashfunc-generic]| Example of BLAKE2b|
|BLAKE2B_512|[Example Code][hashfunc-generic]| Example of BLAKE2B_512|
|Blake3|[Example Code][hashfunc-generic]| Example of Blake3|
|JH_224|[Example Code][hashfunc-generic]| Example of JH_224|
|JH_256|[Example Code][hashfunc-generic]| Example of JH_256|
|JH_384|[Example Code][hashfunc-generic]| Example of JH_384|
|JH_512|[Example Code][hashfunc-generic]| Example of JH_512|
|RadioGatun32|[Example Code][hashfunc-generic]| Example of RadioGatun32|
|RadioGatun64|[Example Code][hashfunc-generic]| Example of RadioGatun64|
|RIPEMD_160|[Example Code][hashfunc-generic]| Example of RIPEMD_160|
|SHA1|[Example Code][hashfunc-generic]| Example of SHA1|
|SHA2_224|[Example Code][hashfunc-generic]| Example of SHA2_224|
|SHA2_256|[Example Code][hashfunc-generic]| Example of SHA2_256|
|SHA2_384|[Example Code][hashfunc-generic]| Example of SHA2_384|
|SHA2_512|[Example Code][hashfunc-generic]| Example of SHA2_512|
|SHA3_224|[Example Code][hashfunc-generic]| Example of SHA3_224|
|SHA3_256|[Example Code][hashfunc-generic]| Example of SHA3_256|
|SHA3_384|[Example Code][hashfunc-generic]| Example of SHA3_384|
|SHA3_512|[Example Code][hashfunc-generic]| Example of SHA3_512|
|Skein_1024|[Example Code][hashfunc-generic]| Example of Skein_1024|
|Skein_256|[Example Code][hashfunc-generic]| Example of Skein_256|
|Skein_512|[Example Code][hashfunc-generic]| Example of Skein_512|
|Skein_VAR|[Example Code][hashfunc-generic]| Example of Skein_VAR|
|Streebog|[Example Code][hashfunc-generic]| Example of Streebog|
|Whirlpool|[Example Code][hashfunc-generic]| Example of Whirlpool|

[hashfunc-generic]:<docs/lookup/hashfunc-generic.md> 

## Hash - Related functions
|Name|Link|Comment|
|:--:|:--:|:--:|
|HKDF|[Example Code][hashrel-hkdf]|HKDF Examples|
|HMAC|[Example Code][hashrel-hmac]|HMAC Examples|
|Poly1305|[Example Code][hashrel-poly1305]|Poly1305 Examples|


[hashrel-hkdf]:<docs/lookup/hashrel-hkdf.md> 
[hashrel-hmac]:<docs/lookup/hashrel-hmac.md> 
[hashrel-poly1305]:<docs/lookup/hashrel-poly1305.md> 

## CRC
|Name|Link|Comment|
|:--:|:--:|:--:|
|CRC8_DVB_S2              |[Example Code][crc-examples]|Example of CRC8_DVB_S2              |
|CRC8_AUTOSAR|[Example Code][crc-examples]|Example of CRC8_AUTOSAR|
|CRC8_Bluetooth|[Example Code][crc-examples]|Example of CRC8_Bluetooth|
|CRC8_CDMA2000|[Example Code][crc-examples]|Example of CRC8_CDMA2000|
|CRC8_DARD|[Example Code][crc-examples]|Example of CRC8_DARD|
|CRC8_GSMA|[Example Code][crc-examples]|Example of CRC8_GSMA|
|CRC8_GSMB|[Example Code][crc-examples]|Example of CRC8_GSMB|
|CRC8_HITAG|[Example Code][crc-examples]|Example of CRC8_HITAG|
|CRC8_I_432_1|[Example Code][crc-examples]|Example of CRC8_I_432_1|
|CRC8_I_CODE|[Example Code][crc-examples]|Example of CRC8_I_CODE|
|CRC8_I_LTE|[Example Code][crc-examples]|Example of CRC8_I_LTE|
|CRC8_MAXIM_DOW|[Example Code][crc-examples]|Example of CRC8_MAXIM_DOW|
|CRC8_MIFARE_MAD|[Example Code][crc-examples]|Example of CRC8_MIFARE_MAD|
|CRC8_NRSC_5|[Example Code][crc-examples]|Example of CRC8_NRSC_5|
|CRC8_OPENSAFETY|[Example Code][crc-examples]|Example of CRC8_OPENSAFETY|
|CRC8_ROHC|[Example Code][crc-examples]|Example of CRC8_ROHC|
|CRC8SAE_J1850|[Example Code][crc-examples]|Example of CRC8SAE_J1850|
|CRC8SAE_SMBUS|[Example Code][crc-examples]|Example of CRC8SAE_SMBUS|
|CRC8SAE_TECH_3250|[Example Code][crc-examples]|Example of CRC8SAE_TECH_3250|
|CRC8SAE_WCDMA|[Example Code][crc-examples]|Example of CRC8SAE_WCDMA|
|CRC32_AIXM|[Example Code][crc-examples]|Example of CRC32_AIXM|
|CRC32_AUTOSAR|[Example Code][crc-examples]|Example of CRC32_AUTOSAR|
|CRC32_BASE91_D|[Example Code][crc-examples]|Example of CRC32_BASE91_D|
|CRC32_BZIP2|[Example Code][crc-examples]|Example of CRC32_BZIP2|
|CRC32_CD_ROM_EDC|[Example Code][crc-examples]|Example of CRC32_CD_ROM_EDC|
|CRC32_CKSUM|[Example Code][crc-examples]|Example of CRC32_CKSUM|
|CRC32_ISCSI|[Example Code][crc-examples]|Example of CRC32_ISCSI|
|CRC32_ISO_HDLC|[Example Code][crc-examples]|Example of CRC32_ISO_HDLC|
|CRC32_JAMCRC|[Example Code][crc-examples]|Example of CRC32_JAMCRC|
|CRC32_MEF|[Example Code][crc-examples]|Example of CRC32_MEF|
|CRC32_MPEG_2|[Example Code][crc-examples]|Example of CRC32_MPEG_2|
|CRC32_XFER|[Example Code][crc-examples]|Example of CRC32_XFER|
|CRC64_GO_ISO|[Example Code][crc-examples]|Example of CRC64_GO_ISO|
|CRC64_MS|[Example Code][crc-examples]|Example of CRC64_MS|
|CRC64_WE|[Example Code][crc-examples]|Example of CRC64_WE|
|CRC64_XZ|[Example Code][crc-examples]|Example of CRC64_XZ|
|CRC64_ECMA182|[Example Code][crc-examples]|Example of CRC64_ECMA182|


[crc-examples]:<docs/lookup/crc-examples.md> 

## Other
|Name|Link|Comment|
|:--:|:--:|:--:|
|CryptoAlgoFactory|[Example Code][other-cryptoalgofactory]|Crypto algo factory utility|
|X509 Certificate - Deserialize|[x509-deserialize]|Deserialize X509 Certificate From Bytes or from PEM file|
|X509 Certificate - RSA Public Key|[x509-geteccpubkey]|X509 Certificate - Get RSA public key from certificate|
|X509 Certificate - ECC Public Key|[x509-getrsapubkey]|X509 Certificate - Get ECC public key from certificate|
|X509 - DER Encode 'EcdsaSigValue' structure|[x509-encodeecdsasigvalue]|How to DER-Encode ECC signature to EcdsaSigValue structure|
|PKCS#1|[PKCS1v2_2]|Using PKCS#1 v2.2 API (RSASSA PSS) generate signature / verify signature etc.|

[other-cryptoalgofactory]:<docs/lookup/other-cryptoalgofactory.md>
[x509-deserialize]:<docs/lookup/x509-deserialize.md>
[x509-geteccpubkey]:<docs/lookup/x509-geteccpubkey.md>
[x509-getrsapubkey]:<docs/lookup/x509-getrsapubkey.md>
[x509-encodeecdsasigvalue]:<docs/lookup/x509-encodeecdsasigvalue.md>


|Name                       | Link              |
|:-------------------------:|:-----------------:|
|Camellia block cipher (128, 192, 256 key sizes)|    -        |
|Streebog-256|    -        |
|Streebog-512                  |    -        |
|CRC-8                  |    -        |
|CRC-16                  |    -        |
|CRC-32                  |    -        |
|RadioGatun-64                  |    -        |
|RadioGatun-32                  |    -        |
|Whirlpool                  |    -        |
|PKCS#1 v2.2 (RFC 8017)     |    [PKCS1v2_2]        |
|SHA1 (Hash function)       |    [SHA1]        |
|Skein (Hash function)      |    [Skein]        |
|BLAKE2b (Hash function)    |    [BLAKE2b]      |
|BLAKE3 (Hash function)     |    [BLAKE3]       |
|Twofish (Block cipher)     |     [Twofish]     |
|X509 V3 Certificate        | [X509Cert]        |
|Rabbit - stream cipher (ESTREAM)| [Rabbit]     |
|HC-256 - stream cipher (ESTREAM)| [HC256]      |
|Hash functions             | [HashFunctions]   |
|ASN.1 Standard             | [ASN1 Standard]   |
|ASN1. Simple Der decoder   | [Der decoder]     |
|TLS 1.2                    | [TLS12 Info]      |
|TLS 1.2 Examples           | [TLS12 examples]  |

[PKCS1v2_2]:<docs/lookup/pkcs1v2_2.md>
[SHA1]:<docs/lookup/sha1.md>
[JH]:<docs/lookup/jh.md>
[Skein]:<docs/lookup/skein.md>
[BLAKE2b]:<docs/lookup/blake2b.md>
[BLAKE3]:<docs/lookup/blake3.md>
[Twofish]:<docs/lookup/twofish.md>
[HC256]:<docs/lookup/hc-256.md>
[Rabbit]:<docs/lookup/rabbit.md>
[X509Cert]:<docs/lookup/x509-cert.md>
[HashFunctions]:<docs/Cryptography/HashFunctions/>
[TLS12 Info]:<docs/Connection/Tls/readme.md>
[TLS12 examples]:<docs/Connection/Tls/examples.md>
[Der decoder]:<./docs/lookup/asn1-x690-decoder.md>


### Overview of root dirs of documentation

|Project      |          Documentation|
|:-----------:|:---------------------:|
|Connection   |[Connection docs]      |
|Cryptography |[Cryptography docs]    |
|Encoding     |[Encoding docs]        |

[docs]:<docs/>
[Connection docs]:<docs/Connection>
[Cryptography docs]:<docs/Cryptography>
[Encoding docs]:<docs/Encoding>
