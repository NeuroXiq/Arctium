namespace Arctium.Protocol.Tls.Protocol.RecordProtocol
{
    public enum ContentType : byte
    {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23
    }
}
