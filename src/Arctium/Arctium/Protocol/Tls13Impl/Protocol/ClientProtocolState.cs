namespace Arctium.Protocol.Tls13Impl.Protocol
{
    internal enum ClientProtocolState
    {
        Start,
        Handshake,
        Connected,
        PostHandshake,
        Closed,
        FatalError
    }
}
