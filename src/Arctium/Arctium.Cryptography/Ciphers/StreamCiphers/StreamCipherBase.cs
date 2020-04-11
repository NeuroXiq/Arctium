using System.IO;

namespace Arctium.Cryptography.Ciphers.StreamCiphers
{
    public abstract class StreamCipherBase
    {
        protected byte[] key;

        public StreamCipherBase(byte[] key)
        {
            this.key = key;
        }

        public abstract long Encrypt(byte[] inputBuffer, long inputOffset, long length, byte[] outputBuffer, long outputOffset);

        public abstract long Decrypt(byte[] inputBuffer, long inputOffset, long length, byte[] outputBuffer, long outputOffset);

        public virtual long Encrypt(Stream inputStream, Stream outputStream)
        {
            byte[] inputBuffer = new byte[Configuration.StreamBufferSize];
            byte[] outputBuffer = new byte[Configuration.StreamBufferSize];
            int readed = LoadDataFromStream(inputBuffer, inputStream);

            long totalEncrypted = 0;

            while (readed > 0)
            {
                Encrypt(inputBuffer, 0, readed, outputBuffer, 0);
                outputStream.Write(outputBuffer, 0, readed);
                readed = LoadDataFromStream(inputBuffer, inputStream);
                totalEncrypted += readed;
            }

            return totalEncrypted;
        }

        public virtual long Decrypt(Stream inputStream, Stream outputStream)
        {
            byte[] inputBuffer = new byte[Configuration.StreamBufferSize];
            byte[] outputBuffer = new byte[Configuration.StreamBufferSize];
            int readed = LoadDataFromStream(inputBuffer, inputStream);

            long totalEncrypted = 0;

            while (readed > 0)
            {
                Decrypt(inputBuffer, 0, readed, outputBuffer, 0);
                outputStream.Write(outputBuffer, 0, readed);
                readed = LoadDataFromStream(inputBuffer, inputStream);
                totalEncrypted += readed;
            }

            return totalEncrypted;
        }

        /// <summary>
        /// Reads data from stream to the buffer, trying to 
        /// fill more than a half of a buffer size
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="stream"></param>
        /// <returns></returns>
        private int LoadDataFromStream(byte[] buffer, Stream stream)
        {
            int totalRead = 0;

            while (true)
            {
                int curRead = stream.Read(buffer, 0, buffer.Length - totalRead);
                totalRead += curRead;
                if (totalRead > buffer.Length / 2 || curRead == 0)
                {
                    break;
                }
            }

            return totalRead;
        }


    }
}
