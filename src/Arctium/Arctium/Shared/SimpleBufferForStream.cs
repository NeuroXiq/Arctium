using Arctium.Shared.Interfaces;
using System.IO;

namespace Arctium.Shared
{
    //todo: remove this
    public class SimpleBufferForStream
    {
        byte[] buffer = new byte[2048];

        public SimpleBufferForStream()
        { }

        public long MediateAllBytesInto(Stream stream, IProcessBytes into)
        {
            long loadedAll = 0;
            int lastLoad = 0;

            do
            {
                lastLoad = stream.Read(buffer, 0, buffer.Length);
                loadedAll += lastLoad;
                into.Process(buffer);
            } while (lastLoad > 0);

            return loadedAll;
        }
    }
}
