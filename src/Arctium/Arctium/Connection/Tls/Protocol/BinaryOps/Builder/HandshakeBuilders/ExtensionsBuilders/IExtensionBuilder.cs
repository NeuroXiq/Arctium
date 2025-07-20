using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    interface IExtensionBuilder
    {
        HandshakeExtension BuildExtension(ExtensionFormatData extFormatData);
    }
}
