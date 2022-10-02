namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
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
