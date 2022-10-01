namespace Arctium.Standards.Connection.Tls.Tls12.Operator
{
    abstract class TlsProtocolOperator
    {
        ///<summary>Reads application data application data to the specified</summary>
        ///<param name="buffer">Buffer to write application data bytes</param>
        ///<param name="count">Bytes length to write</param>
        ///<param name="offset">Offset in buffer to write data</param>
        public abstract void WriteApplicationData(byte[] buffer, int offset, int count);


        ///<summary>Reads application data to the specified buffer</summary>
        ///<param name="buffer">Buffer to write received bytes</param>
        ///<param name="offset">Offset in buffer where to start writing</param>
        ///<param name="count">Length of bytes to read</param>
        public abstract int ReadApplicationData(byte[] buffer, int offset, int count);
        
        ///<summary>Send close notify to connected party</summary>
        public abstract void CloseNotify();
    }
}
