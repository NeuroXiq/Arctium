namespace Arctium.Cryptography.HashFunctions.XOF
{
    public static class XOFConfiguration
    {
        public static class XOFBase
        {
            public static int DefaultInputBlockSize = 0x100;
            public static long DefaultBufferWithCallbackSize = 0x100;
            public static long CallbackBufferBlockCount = 0x10;
        }
    }
}
