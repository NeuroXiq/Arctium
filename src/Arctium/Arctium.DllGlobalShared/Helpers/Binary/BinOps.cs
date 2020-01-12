using System.Runtime.CompilerServices;

namespace Arctium.DllGlobalShared.Helpers.Binary
{
    public static class BinOps
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToULongLittleEndian(byte[] buffer, long offset)
        {
            return (ulong)
                (
                    ((ulong)buffer[offset + 7] <<  0) |
                    ((ulong)buffer[offset + 6] <<  8) |
                    ((ulong)buffer[offset + 5] << 16) |
                    ((ulong)buffer[offset + 4] << 24) |
                    ((ulong)buffer[offset + 3] << 32) |
                    ((ulong)buffer[offset + 2] << 40) |
                    ((ulong)buffer[offset + 1] << 48) |
                    ((ulong)buffer[offset + 0] << 56)
                );
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToULongBigEndian(byte[] buffer, long offset)
        {
            return (ulong)
                (
                    ((ulong)buffer[offset + 0] <<  0) |
                    ((ulong)buffer[offset + 1] <<  8) |
                    ((ulong)buffer[offset + 2] << 16) |
                    ((ulong)buffer[offset + 3] << 24) |
                    ((ulong)buffer[offset + 4] << 32) |
                    ((ulong)buffer[offset + 5] << 40) |
                    ((ulong)buffer[offset + 6] << 48) |
                    ((ulong)buffer[offset + 7] << 56) 
                );
        }

        public static void IntToBigEndianBytes(byte[] buffer, long offset, uint value)
        {
            buffer[offset + 0] = (byte)((value >> 24) & 0xff);
            buffer[offset + 1] = (byte)((value >> 16) & 0xff);
            buffer[offset + 2] = (byte)((value >>  8) & 0xff);
            buffer[offset + 3] = (byte)((value >>  0) & 0xff);
        }
        public static void LongToBigEndianBytes(byte[] buffer, long offset, long value)
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

        public static void ULongToBigEndianBytes(byte[] buffer, long offset, ulong value)
        {
            buffer[offset + 0] = (byte)((value >> 56) & (0xFF));
            buffer[offset + 1] = (byte)((value >> 48) & (0xFF));
            buffer[offset + 2] = (byte)((value >> 40) & (0xFF));
            buffer[offset + 3] = (byte)((value >> 32) & (0xFF));
            buffer[offset + 4] = (byte)((value >> 24) & (0xFF));
            buffer[offset + 5] = (byte)((value >> 16) & (0xFF));
            buffer[offset + 6] = (byte)((value >> 8) & (0xFF));
            buffer[offset + 7] = (byte)((value >> 0) & (0xFF));
        }

        public static uint ToUIntBigEndian(byte[] buffer, long offset)
        {
            uint result = (uint)
               (((uint)buffer[offset + 0] << 24) |
                ((uint)buffer[offset + 1] << 16) |
                ((uint)buffer[offset + 2] <<  8) |
                ((uint)buffer[offset + 3] <<  0));

            return result;
        }

        public static byte[] ToByteArrayBigEndian(ulong[] input, long bitOffset, long bitLength)
        {
            throw new System.Exception();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ROTR(ulong value, int n)
        {
            return ((value >> n) | (value << 64 - n));
        }
    }
}
