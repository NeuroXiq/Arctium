namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    internal enum ClientProtocolState
    {
        Start,
        Handshake,
        Connected,
        Closed,
        FatalError
    }
}
