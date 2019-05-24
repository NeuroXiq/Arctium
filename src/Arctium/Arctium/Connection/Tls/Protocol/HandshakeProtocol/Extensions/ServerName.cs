namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    class ServerName : HandshakeExtension
    {
        public string Name;

        public ServerName(string serverName) : base(HandshakeExtensionType.ServerName)
        {
            Name = serverName;
        }
    }
}
