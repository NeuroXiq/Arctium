using Arctium.Shared.Helpers;
using Arctium.Shared.Other;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
{
    class ProtocolNameListExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.ApplicationLayerProtocolNegotiation;

        public List<byte[]> ProtocolNamesList { get; private set; }
        public string[] ProtocolNameListString { get; private set; }

        public ProtocolNameListExtension(byte[][] protocolNameList)
        {
            ProtocolNamesList = new List<byte[]>(protocolNameList);
            ProtocolNameListString = protocolNameList.Select(bytes => Encoding.UTF8.GetString(bytes)).ToArray();
        }

        /// <summary>
        /// Tries to find protocol name that is know and defined in <see cref="Protocol"/> enum
        /// by bytes. Bytes must exactly match and be defined as IANA defines
        /// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
        /// </summary>
        /// <param name="bytes">UTF-8 protocl name that is suspected to be defined by iana</param>
        /// <param name="outProtocol">if protocol is defined in this enum, assign named protocl value to this enum,
        /// if not found assigned null value</param>
        /// <returns>true if name was found otherwise false</returns>
        public static bool TryGetByBytes(byte[] bytes, out Protocol? outProtocol)
        {
            outProtocol = null;

            Validation.NotNull(bytes, nameof(bytes));

            bool found = false;

            foreach (var kvPair in NamedProtocolUtf8Bytes)
            {
                byte[] knownUtf8 = kvPair.Value;
                
                if (knownUtf8.Length == bytes.Length && MemOps.Memcmp(bytes, knownUtf8))
                {
                    found = true;
                    outProtocol = kvPair.Key;
                    break;
                }
            }

            return found;
        }

        public static byte[] GetConstantBytes(Protocol protocol)
        {
            Validation.EnumValueDefined(protocol, nameof(protocol), "internal");

            var orgBytes = NamedProtocolUtf8Bytes[protocol];

            return (byte[])orgBytes.Clone();
        }

        /// <summary>
        /// copy paste from https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
        /// </summary>
        static Dictionary<Protocol, byte[]> NamedProtocolUtf8Bytes = new Dictionary<Protocol, byte[]>()
        {
            [Protocol.Reserved0] = new byte[] { 0x0A, 0x0A },
            [Protocol.Reserved1] = new byte[] { 0x1A, 0x1A },
            [Protocol.Reserved2] = new byte[] { 0x2A, 0x2A },
            [Protocol.Reserved3] = new byte[] { 0x3A, 0x3A },
            [Protocol.Reserved4] = new byte[] { 0x4A, 0x4A },
            [Protocol.Reserved5] = new byte[] { 0x5A, 0x5A },
            [Protocol.Reserved6] = new byte[] { 0x6A, 0x6A },
            [Protocol.Reserved7] = new byte[] { 0x7A, 0x7A },
            [Protocol.Reserved8] = new byte[] { 0x8A, 0x8A },
            [Protocol.Reserved9] = new byte[] { 0x9A, 0x9A },
            [Protocol.Reserved10] = new byte[] { 0xAA, 0xAA },
            [Protocol.Reserved11] = new byte[] { 0xBA, 0xBA },
            [Protocol.Reserved12] = new byte[] { 0xCA, 0xCA },
            [Protocol.Reserved13] = new byte[] { 0xDA, 0xDA },
            [Protocol.Reserved14] = new byte[] { 0xEA, 0xEA },
            [Protocol.Reserved15] = new byte[] { 0xFA, 0xFA },
            [Protocol.HTTP_0_9] = new byte[] { 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39, },
            [Protocol.HTTP_1_0] = new byte[] { 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30, },
            [Protocol.HTTP_1_1] = new byte[] { 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, },
            [Protocol.SPDY_1] = new byte[] { 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31, },
            [Protocol.SPDY_2] = new byte[] { 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32, },
            [Protocol.SPDY_3] = new byte[] { 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, },
            [Protocol.Traversal_Using_Relays_around_NAT_TURN] = new byte[] { 0x73, 0x74, 0x75, 0x6E, 0x2E, 0x74, 0x75, 0x72, 0x6E, },
            [Protocol.NAT_discovery_using_Session_Traversal_Utilities_for_NAT_STUN] = new byte[] { 0x73, 0x74, 0x75, 0x6E, 0x2E, 0x6e, 0x61, 0x74, 0x2d, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, },
            [Protocol.HTTP_2_over_TLS] = new byte[] { 0x68, 0x32, },
            [Protocol.HTTP_2_over_TCP] = new byte[] { 0x68, 0x32, 0x63, },
            [Protocol.WebRTC_Media_and_Data] = new byte[] { 0x77, 0x65, 0x62, 0x72, 0x74, 0x63, },
            [Protocol.Confidential_WebRTC_Media_and_Data] = new byte[] { 0x63, 0x2d, 0x77, 0x65, 0x62, 0x72, 0x74, 0x63, },
            [Protocol.FTP] = new byte[] { 0x66, 0x74, 0x70, },
            [Protocol.IMAP] = new byte[] { 0x69, 0x6d, 0x61, 0x70, },
            [Protocol.POP3] = new byte[] { 0x70, 0x6f, 0x70, 0x33, },
            [Protocol.ManageSieve] = new byte[] { 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x73, 0x69, 0x65, 0x76, 0x65, },
            [Protocol.CoAP] = new byte[] { 0x63, 0x6f, 0x61, 0x70, },
            [Protocol.XMPP_jabber_client_namespace] = new byte[] { 0x78, 0x6d, 0x70, 0x70, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, },
            [Protocol.XMPP_jabber_server_namespace] = new byte[] { 0x78, 0x6d, 0x70, 0x70, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, },
            [Protocol.acme_tls_1] = new byte[] { 0x61, 0x63, 0x6d, 0x65, 0x2d, 0x74, 0x6c, 0x73, 0x2f, 0x31, },
            [Protocol.OASIS_Message_Queuing_Telemetry_Transport_MQTT] = new byte[] { 0x6d, 0x71, 0x74, 0x74, },
            [Protocol.DNS_over_TLS] = new byte[] { 0x64, 0x6F, 0x74, },
            [Protocol.Network_Time_Security_Key_Establishment] = new byte[] { 0x6E, 0x74, 0x73, 0x6B, 0x65, 0x2F, 0x31, },
            [Protocol.SunRPC] = new byte[] { 0x73, 0x75, 0x6e, 0x72, 0x70, 0x63, },
            [Protocol.HTTP_3] = new byte[] { 0x68, 0x33, },
            [Protocol.SMB2] = new byte[] { 0x73, 0x6D, 0x62, },
            [Protocol.IRC] = new byte[] { 0x69, 0x72, 0x63, },
            [Protocol.NNTP_reading] = new byte[] { 0x6E, 0x6E, 0x74, 0x70, },
            [Protocol.NNTP_transit] = new byte[] { 0x6E, 0x6E, 0x73, 0x70, },
            [Protocol.DoQ] = new byte[] { 0x64, 0x6F, 0x71, },
            [Protocol.SIP] = new byte[] { 0x73, 0x69, 0x70, 0x2f, 0x32, },

        };

        // constats
        public enum Protocol
        {
            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved0 = 1,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved1 = 2,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved2 = 3,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved3 = 4,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved4 = 5,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved5 = 6,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved6 = 7,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved7 = 8,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved8 = 9,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved9 = 10,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved10 = 11,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved11 = 12,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved12 = 13,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved13 = 14,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved14 = 15,


            ///<summary>
            /// [RFC8701]
            ///<summary>
            Reserved15 = 16,


            ///<summary>
            /// [RFC1945]
            ///<summary>
            HTTP_0_9 = 17,


            ///<summary>
            /// [RFC1945]
            ///<summary>
            HTTP_1_0 = 18,


            ///<summary>
            /// [RFC9112]
            ///<summary>
            HTTP_1_1 = 19,


            ///<summary>
            /// [http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft1]
            ///<summary>
            SPDY_1 = 20,


            ///<summary>
            /// [http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2]
            ///<summary>
            SPDY_2 = 21,


            ///<summary>
            /// [http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3]
            ///<summary>
            SPDY_3 = 22,


            ///<summary>
            /// [RFC7443]
            ///<summary>
            Traversal_Using_Relays_around_NAT_TURN = 23,


            ///<summary>
            /// [RFC7443]
            ///<summary>
            NAT_discovery_using_Session_Traversal_Utilities_for_NAT_STUN = 24,


            ///<summary>
            /// [RFC9113]
            ///<summary>
            HTTP_2_over_TLS = 25,


            ///<summary>
            /// [1][RFC9113]
            ///<summary>
            HTTP_2_over_TCP = 26,


            ///<summary>
            /// [RFC8833]
            ///<summary>
            WebRTC_Media_and_Data = 27,


            ///<summary>
            /// [RFC8833]
            ///<summary>
            Confidential_WebRTC_Media_and_Data = 28,


            ///<summary>
            /// [RFC959][RFC4217]
            ///<summary>
            FTP = 29,


            ///<summary>
            /// [RFC2595]
            ///<summary>
            IMAP = 30,


            ///<summary>
            /// [RFC2595]
            ///<summary>
            POP3 = 31,


            ///<summary>
            /// [RFC5804]
            ///<summary>
            ManageSieve = 32,


            ///<summary>
            /// [RFC8323]
            ///<summary>
            CoAP = 33,


            ///<summary>
            /// [https://xmpp.org/extensions/xep-0368.html]
            ///<summary>
            XMPP_jabber_client_namespace = 34,


            ///<summary>
            /// [https://xmpp.org/extensions/xep-0368.html]
            ///<summary>
            XMPP_jabber_server_namespace = 35,


            ///<summary>
            /// [RFC8737]
            ///<summary>
            acme_tls_1 = 36,


            ///<summary>
            /// [http://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html]
            ///<summary>
            OASIS_Message_Queuing_Telemetry_Transport_MQTT = 37,


            ///<summary>
            /// [RFC7858]
            ///<summary>
            DNS_over_TLS = 38,


            ///<summary>
            /// [RFC8915, Section 4]
            ///<summary>
            Network_Time_Security_Key_Establishment, _version_1 = 39,


            ///<summary>
            /// [RFC9289]
            ///<summary>
            SunRPC = 40,


            ///<summary>
            /// [RFC9114]
            ///<summary>
            HTTP_3 = 41,


            ///<summary>
            /// [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962]
            ///<summary>
            SMB2 = 42,


            ///<summary>
            /// [RFC1459]
            ///<summary>
            IRC = 43,


            ///<summary>
            /// [RFC3977]
            ///<summary>
            NNTP_reading = 44,


            ///<summary>
            /// [RFC3977]
            ///<summary>
            NNTP_transit = 45,


            ///<summary>
            /// [RFC9250]
            ///<summary>
            DoQ = 46,


            ///<summary>
            /// [RFC3261]
            ///<summary>
            SIP = 47,
        }
    }
}
