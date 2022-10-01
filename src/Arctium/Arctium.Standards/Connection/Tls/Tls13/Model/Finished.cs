namespace Arctium.Standards.Connection.Tls.Tls13.Model
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
