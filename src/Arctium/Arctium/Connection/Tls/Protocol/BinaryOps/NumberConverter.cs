namespace Arctium.Connection.Tls.Protocol.BinaryOps
{
    ///<summary>TLS number converter, all operation are processed in big-endian manner.</summary>
    static class NumberConverter
    {

        public static ushort ToUInt16(byte[] buffer, int offset)
        {
            ushort converted = (ushort)((buffer[offset] << 8) + buffer[offset + 1]);

            return converted;
        }

        public static uint ToUInt24(byte[] buffer, int offset)
        {
            uint converted = (uint)((buffer[offset + 0] << 16) + 
                                    (buffer[offset + 1] <<  8) + 
                                    (buffer[offset + 2] <<  0));

            return converted;

        }

        public static uint ToUInt32(byte[] buffer, int offset)
        {
            uint converted = (uint)((buffer[offset + 0] << 24) +
                                    (buffer[offset + 1] << 16) +
                                    (buffer[offset + 2] <<  8) +
                                    (buffer[offset + 3] <<  0));

            return converted;
        }

        public static ulong ToUInt64(byte[] buffer, int offset)
        {
            ulong converted = (((ulong)buffer[offset + 0])   << 56) +
                              (((ulong)buffer[offset + 1])   << 48) +
                              (((ulong)buffer[offset + 2])   << 40) +
                              (((ulong)buffer[offset + 3])   << 32) +
                              (((ulong)buffer[offset + 4])   << 24) +
                              (((ulong)buffer[offset + 5])   << 16) +
                              (((ulong)buffer[offset + 6])   <<  8) +
                              (((ulong)buffer[offset + 7])   <<  0);

            return converted;
        }

        public static void FormatUInt16(ushort value, byte[] buffer, int offset)
        {
            buffer[offset + 0] = (byte)(value >> 8);
            buffer[offset + 1] = (byte)(value & 0xff);
        }

        public static void FormatUInt32(uint value, byte[] buffer, int offset)
        {
            buffer[offset + 0] = (byte)((value & 0xff000000) >> 24);
            buffer[offset + 1] = (byte)((value & 0x00ff0000) >> 16);
            buffer[offset + 2] = (byte)((value & 0x0000ff00) >> 8);
            buffer[offset + 3] = (byte)((value & 0x000000ff) >> 0);
        }

        public static void FormatUInt24(int value, byte[] buffer, int offset)
        {
            buffer[offset + 0] = (byte)((value & 0x00ff0000) >> 16);
            buffer[offset + 1] = (byte)((value & 0x0000ff00) >> 8);
            buffer[offset + 2] = (byte)((value & 0x000000ff) >> 0);
        }
    }
}
