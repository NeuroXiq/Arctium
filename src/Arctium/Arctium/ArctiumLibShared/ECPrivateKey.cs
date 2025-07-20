namespace Arctium.Standards.ArctiumLibShared
{
    public class ECPrivateKey
    {
        /// <summary>
        /// Big endian unsigned integer 
        /// </summary>
        public byte[] PrivateKey { get; private set; }

        public ECPrivateKey(byte[] privateKey)
        {
            PrivateKey = privateKey;
        }
    }
}
