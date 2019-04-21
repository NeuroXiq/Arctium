namespace Arctium.Connection.Tls.RecordProtocol
{
    public enum ContentType : byte
    {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23
    }
}
