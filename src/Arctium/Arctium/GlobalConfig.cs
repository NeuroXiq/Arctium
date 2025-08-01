
namespace Arctium.Shared
{
    public static class GlobalConfig
    {
        static GlobalConfig()
        {
        }


        public static int DefaultHashBufferBlockCount = 0x100;

        public static int DefaultBufferForStreamSize = 0x1000;

        public static byte[] RandomByteArray(int length)
        {
            byte[] array = new byte[length];
            RandomGeneratorCryptSecure(array, 0, length);

            return array;
        }

        public static void RandomGeneratorCryptSecure(byte[] buffer, int offset, int length)
        {
            (new Random()).NextBytes(new Span<byte>(buffer, offset, length));
        }
    }
}
