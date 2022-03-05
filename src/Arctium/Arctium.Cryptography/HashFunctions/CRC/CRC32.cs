using System.IO;

namespace Arctium.Cryptography.HashFunctions.CRC
{
    public class CRC32
    {
        uint C = 0x04c11db7;
        uint state;
        byte[] buffer;
        uint processedBytesCount;
        uint cur = 0;

        public CRC32() 
        {
            buffer = new byte[2048];
            Reset();
        }

        public void Process(byte[] bytes, long offset, long length)
        {
            if (length < 1) return;

            for(int i = 0; i < bytes.Length; i++) 
            {
                Pbyte(bytes[i]);
            }
        }

        private void Pbyte(byte b)
        {


        }

        public void Process(Stream stream)
        {
            int lastRead;

            do
            {
                lastRead = stream.Read(buffer, 0, 2048);
                Process(buffer, 0, lastRead);
            } while (lastRead > 0);
        }

        public uint GetResult()
        {
            return 0;
        }

        /// <summary>
        /// Resets interal state. State will be equal to state of the new instace 
        /// </summary>
        public void Reset()
        {
            state = 0;
            processedBytesCount = 0;
        }
    }
}
