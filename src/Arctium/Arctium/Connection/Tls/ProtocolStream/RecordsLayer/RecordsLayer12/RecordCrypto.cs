using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    abstract class RecordCrypto
    {
        public struct RecordData
        {
            public ulong SeqNum;
            public byte[] Buffer;
            public int FragmentOffset;
            public RecordHeader Header;
        }


        ///<return>tls ciphertext fragment length</return>
        public abstract int Encrypt(RecordData recordData, byte[] outBuffer, int outOffset);
        
        ///<summary></summary>
        ///<returns>decrypted content length</returns>
        public abstract int Decrypt(RecordData recordData, byte[] outBuffer, int outOffset);

        public abstract int GetEncryptedLength(int contentPlaintextLength);
        public abstract int GetDecryptedLength(int ciphertextFragmentLength);
    }
}
