namespace Arctium.Protocol.Tls13Impl.Model
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
