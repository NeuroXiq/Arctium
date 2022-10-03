namespace Arctium.Standards.Connection.Tls.Tls13.Model
{
    internal class Tls13Const
    {
        /* General */
        public const ushort Tls13VersionUShort = 0x0304;

        /* Client Hello */
        public const int HelloRandomFieldLength = 32;
        public const int ClientHello_LegacySessionIdMaxLen = 32;
        public const int ClientHello_CipherSuitesMaxLen = 65534;
        public const int ClientHello_CompressionMethodsMaxLen = 255;
        public const int ClientHello_ExtensionsMaxLen = 65535;

        public const int RecordLayer_MaxPlaintextApplicationDataLength = 1 << 14;


        /* NewSessionTicket */
        public const int NewSessionTicket_MinTicketLength = 1;
        public const int NewSessionTicket_MaxTicketLength = (1 << 16) - 1;
        public const int NewSessionTicket_MaxTicketNonceLength = 255;
        public const int NewSessionTicket_MaxTicketLifetimeSeconds = 604800;


        /* Extensions */

        /* Pre shared key extension */
        public const int PreSharedKeyExtension_IdentitiesMinLength = 7;
        public const int PreSharedKeyExtension_BindersMinLength = 33;
        public const int PreSharedKeyExtension_PskBinderEntryMinLength = 32;
        public const int PreSharedKeyExtension_PskBinderEntryMaxLength = 255;
        public const int PreSharedKeyExtension_IdentityMinLength = 1;

        /* Pre Shared Key Exchange Modes */
        public const int PskKeyExchangeModes_KeModesMinVectorLength = 1;

        /* Key share client hello */
        public static int KeyShareClientHello_ClientSharesVectorMaxLen = (1 << 16) - 1;

        public static int KeyShareEntry_KeyExchangeVectorMaxLen = (1 << 16) - 1;
    }
}
