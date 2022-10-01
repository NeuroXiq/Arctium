namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
{
    class ServerSupportedVersionsExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.SupportedVersions;

        public ushort SelectedVersion { get; private set; }

        public const ushort TLS13Version = 0x0304;

        public ServerSupportedVersionsExtension(ushort selectedVersion)
        {
            SelectedVersion = selectedVersion;
        }

        private static ServerSupportedVersionsExtension serverHelloTls13Static = new ServerSupportedVersionsExtension(TLS13Version);
        public static ServerSupportedVersionsExtension ServerHelloTls13 { get { return serverHelloTls13Static; } }
    }

    class ClientSupportedVersionsExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.SupportedVersions;

        public ushort[] Versions { get; private set; }

        public ClientSupportedVersionsExtension(ushort[] versions)
        {
            this.Versions = versions;
        }
    }
}
