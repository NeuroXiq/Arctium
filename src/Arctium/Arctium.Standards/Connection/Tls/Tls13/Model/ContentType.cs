namespace Arctium.Standards.Connection.Tls.Tls13.Model
{
    enum ContentType : byte
    {
        Invalid = 0,
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23
    }
}
