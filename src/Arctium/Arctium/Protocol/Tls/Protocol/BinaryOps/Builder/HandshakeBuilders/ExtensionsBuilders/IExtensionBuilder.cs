using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    interface IExtensionBuilder
    {
        HandshakeExtension BuildExtension(ExtensionFormatData extFormatData);
    }
}
