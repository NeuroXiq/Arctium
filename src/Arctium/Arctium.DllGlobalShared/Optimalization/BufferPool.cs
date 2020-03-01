namespace Arctium.DllGlobalShared.Optimalization
{
    public static class BufferPool
    {
        
        private static readonly object _lock = new object();
        //TODO
        static BufferPool() { }

        public static byte[] Alloc(int minSize) { lock (_lock) { } return new byte[minSize];  }

        public static void Free(byte[] buffer) { lock (_lock) { } }


    }
}
