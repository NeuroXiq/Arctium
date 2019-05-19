namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    interface IFragmentEncryptor
    {
        int Encrypt(RecordData recordData, byte[] outBuffer, int outOffset);
        int GetEncryptedLength(int paintextFragmentLength);
    }
}
