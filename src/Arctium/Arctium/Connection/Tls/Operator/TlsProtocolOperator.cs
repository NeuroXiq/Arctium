namespace Arctium.Connection.Tls.Operator
{
    abstract class TlsProtocolOperator
    {
        public abstract void WriteApplicationData(byte[] buffer, int offset, int length);

        public abstract void ReadApplicationData(byte[] buffer, int offset, int length);
    }
}
