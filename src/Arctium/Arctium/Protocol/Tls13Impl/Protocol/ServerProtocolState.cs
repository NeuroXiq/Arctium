namespace Arctium.Protocol.Tls13Impl.Protocol
{
    public enum ServerProtocolState
    {
        Listen,
        Handshake,
        Connected,
        PostHandshake,
        Closed
    }
}
