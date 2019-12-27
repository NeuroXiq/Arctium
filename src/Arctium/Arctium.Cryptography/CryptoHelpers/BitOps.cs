namespace Arctium.Cryptography.CryptoHelpers
{
    static class BitOps
    {

        public static void IntToBigEndianBytes(byte[] buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte)((value >> 24) & 0xff);
            buffer[offset + 1] = (byte)((value >> 16) & 0xff);
            buffer[offset + 2] = (byte)((value >>  8) & 0xff);
            buffer[offset + 3] = (byte)((value >>  0) & 0xff);
        }
        public static void LongToBigEndianBytes(byte[] buffer, int offset, long value)
        {
            buffer[offset + 0] = (byte)((value >> 56) & (0xFF));
            buffer[offset + 1] = (byte)((value >> 48) & (0xFF));
            buffer[offset + 2] = (byte)((value >> 40) & (0xFF));
            buffer[offset + 3] = (byte)((value >> 32) & (0xFF));
            buffer[offset + 4] = (byte)((value >> 24) & (0xFF));
            buffer[offset + 5] = (byte)((value >> 16) & (0xFF));
            buffer[offset + 6] = (byte)((value >>  8) & (0xFF));
            buffer[offset + 7] = (byte)((value >>  0) & (0xFF));
        }

        public static uint ToUIntBigEndian(byte[] buffer, int offset)
        {
            uint result = (uint)
               ((buffer[offset + 0] << 24) |
                (buffer[offset + 1] << 16) |
                (buffer[offset + 2] << 8)  |
                (buffer[offset + 3] << 0));

            return result;
        } 
    }
}
