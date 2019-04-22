namespace Arctium.Connection.Tls.BinaryOps
{
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
    }
}
