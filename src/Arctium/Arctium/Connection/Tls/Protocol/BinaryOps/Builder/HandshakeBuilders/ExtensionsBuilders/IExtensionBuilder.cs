using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    interface IExtensionBuilder
    {
        HandshakeExtension BuildExtension(ExtensionFormatData extFormatData);
    }
}
