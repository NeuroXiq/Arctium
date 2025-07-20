namespace Arctium.Standards.Connection.Tls13Impl.Protocol
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
