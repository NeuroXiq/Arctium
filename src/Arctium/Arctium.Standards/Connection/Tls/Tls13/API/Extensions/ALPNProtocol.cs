namespace Arctium.Standards.Connection.Tls.Tls13.API.Extensions
{
    // this values must match values in 'MODEL' namespace
    // because of casting in API

    /// <summary>
    /// rfc7301
    /// Constant protocol names for ALPN TLS13 extension defined on IANA website 
    /// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
    /// </summary>
    public enum ALPNProtocol
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
