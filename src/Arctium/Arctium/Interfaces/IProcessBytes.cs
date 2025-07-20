using System.IO;

namespace Arctium.Shared.Interfaces
{
    public interface IProcessBytes
    {
        void Process(byte[] bytes);
        void Process(byte[] bytes, long offset, long length);
        void Process(Stream stream);
    }
}
