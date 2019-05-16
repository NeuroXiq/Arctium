using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    abstract class RecordCrypto
    {
        public struct RecordData
        {
            public ulong SeqNum;
            public byte[] Buffer;
            public int RecordOffset;
        }

        public abstract void Encrypt(RecordData recordData, byte[] outBuffer, int outOffset);
        
        ///<summary></summary>
        ///<returns>Content length</returns>
        public abstract int Decrypt(RecordData recordData, out int contentOffset);

        public abstract int GetEncryptedLength(int contentPlaintextLength);
    }
}
