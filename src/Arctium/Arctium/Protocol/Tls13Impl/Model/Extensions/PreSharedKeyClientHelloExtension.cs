using Arctium.Shared.Exceptions;
using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
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
