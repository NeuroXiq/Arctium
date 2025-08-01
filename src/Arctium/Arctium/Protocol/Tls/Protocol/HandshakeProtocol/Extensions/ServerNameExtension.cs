using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions
{
    class ServerNameExtension : HandshakeExtension
    {
        public string Name;
        public NameType NameType;

        public ServerNameExtension(string serverName, NameType nameType) : base(HandshakeExtensionType.ServerName)
        {
            Name = serverName;
            NameType = nameType;
        }
    }
}
