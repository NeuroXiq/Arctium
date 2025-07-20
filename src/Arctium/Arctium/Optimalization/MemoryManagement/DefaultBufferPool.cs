namespace Arctium.Shared.Optimalization.MemoryManagement
{
    public class DefaultBufferPool : IBufferPool
    {
        public void FreeBuffer(byte[] buffer)
        {

        }



        public byte[] GetBuffer(long size)
        {
            return new byte[size];
        }

        public byte[] GetBuffer(long size, bool exactLength)
        {
            return new byte[size];
        }
    }
}
