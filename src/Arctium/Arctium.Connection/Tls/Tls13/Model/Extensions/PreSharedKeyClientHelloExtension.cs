using Arctium.Shared.Exceptions;

namespace Arctium.Connection.Tls.Tls13.Model.Extensions
{
    internal class PreSharedKeyClientHelloExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.PreSharedKey;

        public struct PskIdentity
        {
            public byte[] Identity;
            public uint ObfuscatedTicketAge;

            public PskIdentity(byte[] identity, uint obfuscatedTicketAge)
            {
                Identity = identity;
                ObfuscatedTicketAge = obfuscatedTicketAge;
            }

        }

        public PskIdentity[] Identities { get; private set; }
        public byte[][] Binders { get; private set; }

        public PreSharedKeyClientHelloExtension(PskIdentity[] identities, byte[][] binders)
        {
            if (identities.Length != binders.Length || identities.Length == 0) throw new ArctiumExceptionInternal("must be greated than zero, and equal sizes");

            Identities = identities;
            Binders = binders;
        }
    }
}
