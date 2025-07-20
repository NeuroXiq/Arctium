namespace Arctium.Standards.Connection.Tls13Impl.Model
{
    internal class Finished
    {
        public byte[] VerifyData { get; private set; }

        public Finished(byte[] verifyData)
        {
            VerifyData = verifyData;
        }
    }
}
