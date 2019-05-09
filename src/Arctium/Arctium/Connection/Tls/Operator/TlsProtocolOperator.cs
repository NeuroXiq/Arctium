namespace Arctium.Connection.Tls.Operator
{
    abstract class TlsProtocolOperator
    {
        public abstract void WriteApplicationData(byte[] buffer, int offset, int count);

        public abstract int ReadApplicationData(byte[] buffer, int offset, int count);
    }
}
