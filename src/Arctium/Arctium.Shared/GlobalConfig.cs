﻿using Arctium.Shared.Security;

namespace Arctium.Shared
{
    public static class GlobalConfig
    {
        static RandomGenerator randomGenerator;

        static GlobalConfig()
        {
            randomGenerator = new DefaultUnsafePRNG();
        }


        public static int DefaultHashBufferBlockCount = 0x100;

        public static int DefaultBufferForStreamSize = 0x1000;

        public static void RandomGeneratorCryptSecure(byte[] buffer, long offset, long length)
        {
            randomGenerator.Generate(buffer, offset, length);
        }
    }
}
