namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions
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
