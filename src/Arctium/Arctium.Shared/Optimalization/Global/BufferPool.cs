namespace Arctium.Shared.Optimalization.Global
{
    /// <summary>
    /// Global buffer pool used everywhere
    /// </summary>
    public static class BufferPool
    {
        
        private static readonly object _lock = new object();
        //TODO
        static BufferPool() { }

        public static byte[] Alloc(int minSize) { lock (_lock) { } return new byte[minSize];  }

        public static void Free(byte[] buffer) { lock (_lock) { } }


    }
}
