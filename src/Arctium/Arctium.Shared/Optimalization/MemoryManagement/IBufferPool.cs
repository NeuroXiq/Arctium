namespace Arctium.Shared.Optimalization.MemoryManagement
{
    public interface IBufferPool
    {

        byte[] GetBuffer(long size, bool exactSize);

        byte[] GetBuffer(long size);

        void FreeBuffer(byte[] buffer);
    }
}
