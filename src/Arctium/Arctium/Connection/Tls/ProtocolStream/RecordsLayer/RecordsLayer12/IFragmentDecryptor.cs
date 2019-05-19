namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    interface IFragmentDecryptor
    {
        int Decrypt(RecordData recordData, byte[] outBuffer, int outOffset);
        int GetDecryptedLength(int encryptedFragmentLength);
    }
}
