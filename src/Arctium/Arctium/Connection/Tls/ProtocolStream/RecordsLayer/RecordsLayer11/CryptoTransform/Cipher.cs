namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    abstract class Cipher
    {
        public abstract byte[] EncryptToCiphertextFragment(byte[] buffer, int offset, int length);

        public abstract byte[] DecryptToCompressedFragment(byte[] buffer, int offset, int lengths);
    }
}
