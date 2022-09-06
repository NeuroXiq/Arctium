namespace Arctium.Connection.Tls.Tls13.Model.Extensions
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

        public static ServerSupportedVersionsExtension ServerHelloTls13()
        {
            return new ServerSupportedVersionsExtension(TLS13Version);
        }
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
