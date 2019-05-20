namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    interface IFragmentDecryptor
    {
        int Decrypt(RecordData recordData, byte[] outBuffer, int outOffset);
        //int GetDecryptedLength(int encryptedFragmentLength);

        //returns length
        // encryptData
        // {
        //   ContentType
        //   Version
        //   ulong seqNum
        //   byte[] fragmentBuffer, fragment offset, fragment length, outBuffer, outOffset, outLength, <-- out is record
        // }
        //
        //

        //int Decrypt(byte[] recordOffset, byte[] outBuffer, int outOffset, ulong seqNum)
    }
}
