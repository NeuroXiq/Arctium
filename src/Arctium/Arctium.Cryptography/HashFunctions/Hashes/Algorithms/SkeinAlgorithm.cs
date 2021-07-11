/*
 *
 *
 * - - - -
 *  Simple prefix means 'simple' from specification. Simple hashing doesn't support
 *  tree version of algorithm, that means that Three leaf size, fanout and height = 0.
 *  For detailslook at 'Simple Hashing' in specification.
 *
 * */

using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Cryptography.HashFunctions.Hashes.Algorithms
{
    public static class SkeinAlgorithm
    {
        // 'SHA3' in Hex
        // </summary
        const uint ConfigSchemaIdentifierSHA3 = 0x33414853;
        const ushort ConfigVersionNumber = 1;

        // <summary>
        // Const values for 'Type' bits for UBI function 
        // <summary>
        enum TypeValue: ulong
        {
            Key = 0,
            Cfg = 4,
            Prs = 8,
            PK = 12,
            Kdf = 16,
            Non = 20,
            Msg = 48,
            Out = 63
        };

        public struct ConfigurationValue
        {
            public uint SchemaIdentifier;
            public ushort VersionNumber;
            public ushort ReservedSetToZero_0;
            public ulong OutputLength;
            public byte TreeLeafSize;
            public byte TreeFanOut;
            public byte TreeMaxHeight;
            public byte[] ReservedSetToZero_1;
        }

        public struct Context
        {
            public ConfigurationValue Config;
            public ThreefishAlgorithm.Context ThreefishContext;
            public ulong ProcessedBytesCount;
            public byte[] OutputBuffer;
            public int InternalStateSizeInBits;
            
            /// <summary>
            /// Chaining value
            /// </summary>
            public byte[] G;
        }

        //
        // Public 
        //
        

        /*
         * Tweak is 128-bit value (implemetation split 16 bytes tweak into two ulongs):
         * [  0 -  95]  Position (means processed bytes)
         * [ 96 - 111]  Reserver  (all zeros)
         * [112 - 118]  Tree Level
         * [119 - 119]  Bit Pad
         * [120 - 125]  Type
         * [126 - 126]  First
         * [127 - 127]  Last
         * */

        
        public static void SimpleProcessNotLastBlocks256(Context context, byte[] input, long inputOffset, long length)
        {
            long blockCount = length / 256;
            ulong t0, t1;
            byte[] lastOutput = context.G;

            for (long i = 0; i < blockCount; i++)
            {
                context.ProcessedBytesCount += 32;
                t0 = context.ProcessedBytesCount;
                t1 = ((ulong)0 << 6) | // final 
                    ((context.ProcessedBytesCount == 32) ? ((ulong)1 << 6) : (ulong)0) | // first
                    ((ulong)TypeValue.Msg << 0) | // type
                    ((ulong)0 << 15) | // bitpad
                    ((ulong)0 << 8) | // tree level
                    ((ulong)0 << 16);

                MemMap.ToULong32BytesLE(context.G, context.ThreefishContext.Key);
                ThreefishAlgorithm.Encrypt256(input, inputOffset, context.OutputBuffer, 0, t0, t1, context.ThreefishContext); 
            
                for (int j = 0; j < 16; j++) context.OutputBuffer[j] ^= input[inputOffset + j];
            }
        }

        public static void SimpleProcessLastBlock256(Context context, byte[] input, long offset, long length)
        {
        }
        
        public static void Output(Context context, byte[] outputBuffer, ulong outputOffset)
        {
            
        }

        /// <summary>
        /// Initialise Skein context that do not support tree version of algorithm
        /// </summary>
        public static Context SimpleInitialise(int outputLengthInBits, int internalStateSizeInBits)
        {

            ConfigurationValue config = new ConfigurationValue();

            config.SchemaIdentifier = ConfigSchemaIdentifierSHA3;
            config.VersionNumber = ConfigVersionNumber;
            config.ReservedSetToZero_0 = 0;
            config.OutputLength = (ulong)outputLengthInBits;
            config.ReservedSetToZero_1 = new byte[13];

            Context context = new Context();

            context.InternalStateSizeInBits = internalStateSizeInBits;
            context.Config = config;
            SetInitialChainingValue(context);

            return context;
        }

        //
        // Private
        //
        
        private static void SetInitialChainingValue(Context context)
        {
            int blockSizeInBytes = context.InternalStateSizeInBits / 8;
            ConfigurationValue config = context.Config;
            byte[] keyAllZeros = new byte[blockSizeInBytes];
            byte[] inputBlock = new byte[blockSizeInBytes];
            ulong t0, t1;
            context.G = new byte[blockSizeInBytes];

            MemMap.ToBytes1UIntLE(config.SchemaIdentifier, inputBlock, 0);
            MemMap.ToBytes1UShortLE(config.VersionNumber, inputBlock, 4);
            MemMap.ToBytes1ULongLE(config.OutputLength, inputBlock, 8);
            inputBlock[16] = config.TreeLeafSize;
            inputBlock[17] = config.TreeFanOut;
            inputBlock[18] = config.TreeMaxHeight;

            ThreefishAlgorithm.Context tfcontext = ThreefishAlgorithm.Initialise(keyAllZeros);

            if (context.InternalStateSizeInBits == 256)
            {
               t0 = 32; 
               t1 = ((ulong)1 << 63) | // first
                   ((ulong)1 << 62) | // final
                   (ulong)TypeValue.Cfg << 56;

               ThreefishAlgorithm.Encrypt256(inputBlock, 0, context.G, 0, t0, t1, tfcontext);
            }
            else if (context.InternalStateSizeInBits == 512)
            {
                throw new Exception();
            }
            else 
            {
                throw new Exception();
            }

            for (int i = 0; i < context.G.Length; i++)
            {
                context.G[i] ^= inputBlock[i];
            }

            // MemDump.HexDump(context.G);

        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void UBI512() {}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void UBI1024() {}
    }
}
