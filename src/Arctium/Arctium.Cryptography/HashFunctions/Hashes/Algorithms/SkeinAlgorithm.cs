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

        public class ConfigurationValue
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

        public class Context
        {
            public ConfigurationValue Config;
            public ThreefishAlgorithm.Context ThreefishContext;
            public ulong ProcessedBytesCount;
            public byte[] ThreefishOutputBuffer;
            public byte[] HashOutputBuffer;
            public byte[] HashOutputCounter;
            public byte[] LastBlockBuffer;
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
        
        public static void SimpleProcessNotLastBlock1024(Context context, byte[] input, long inputOffset, long length)
        {
        
        }

        public static void SimpleProcessLastBlock1024(Context context, byte[] input, long inputOffset, long length)
        {
        
        }
        
        public static void SimpleProcessNotLastBlock512(Context context, byte[] input, long inputOffset, long length)
        {
            long blockCount = length / 64;
            ulong t0, t1;

            for (long i = 0; i < blockCount; i++)
            {
                context.ProcessedBytesCount += 64;
                t0 = context.ProcessedBytesCount;
                t1 = ((ulong)0 << 63) | 
                    (context.ProcessedBytesCount == 64 ? ((ulong)1 << 62) : 0) | 
                    (ulong)TypeValue.Msg << 56;

                MemMap.ToULong64BytesLE(context.G, 0, context.ThreefishContext.Key, 0);
                ThreefishAlgorithm.Encrypt512(input, inputOffset, context.ThreefishOutputBuffer, 0, t0, t1, context.ThreefishContext);

                for (int j = 0; j < 64; j++) context.G[j] = (byte)(context.ThreefishOutputBuffer[j] ^ input[j + inputOffset]);

                inputOffset += 64;
            }
        }

        public static void SimpleProcessLastBlock512(Context context, byte[] input, long inputOffset, long length)
        {
            ulong t0, t1;
            MemOps.Memset(context.LastBlockBuffer, 0, 64, 0);
            MemCpy.Copy(input, inputOffset, context.LastBlockBuffer, 0, length);

            context.ProcessedBytesCount += (ulong)length;
            t0 = context.ProcessedBytesCount;
            t1 = ((ulong)1 << 63) |
                ((ulong)(context.ProcessedBytesCount > 64 ? 0 : 1) << 62) | 
                (ulong)TypeValue.Msg << 56;

            MemMap.ToULong64BytesLE(context.G, 0, context.ThreefishContext.Key, 0);
            ThreefishAlgorithm.Encrypt512(context.LastBlockBuffer, 0, context.ThreefishOutputBuffer, 0, t0, t1, context.ThreefishContext);
            
            for (int i = 0; i < 64; i++) context.G[i] = (byte)(context.ThreefishOutputBuffer[i] ^ context.LastBlockBuffer[i]);
        }
        
        public static void SimpleProcessNotLastBlock256(Context context, byte[] input, long inputOffset, long length)
        {
            long blockCount = length / 32;
            ulong t0, t1;
            byte[] lastOutput = context.G;

            for (long i = 0; i < blockCount; i++)
            {
                context.ProcessedBytesCount += 32;
                t0 = context.ProcessedBytesCount;
                t1 = ((ulong)0 << 63) | // final 
                    ((context.ProcessedBytesCount == 32) ? ((ulong)1 << 62) : (ulong)0) | // first
                    ((ulong)TypeValue.Msg << 56) | // type
                    ((ulong)0 << 15) | // bitpad
                    ((ulong)0 << 8) | // tree level
                    ((ulong)0 << 16);

                MemMap.ToULong32BytesLE(context.G, context.ThreefishContext.Key);
                ThreefishAlgorithm.Encrypt256(input, inputOffset, context.ThreefishOutputBuffer, 0, t0, t1, context.ThreefishContext); 
            
                for (int j = 0; j < 32; j++) context.G[j] = (byte)(context.ThreefishOutputBuffer[j] ^ input[inputOffset + j]);
                inputOffset += 32;
            }
        }

        public static void SimpleProcessLastBlock256(Context context, byte[] input, long offset, long length)
        {
            MemOps.Memset(context.LastBlockBuffer, 0, 32, 0); 
            MemCpy.Copy(input, offset, context.LastBlockBuffer, 0, length);

            context.ProcessedBytesCount += (ulong)length;

            ulong t0, t1;
            t0 = context.ProcessedBytesCount;
            t1 = ((ulong)1 << 63) | // final
                (ulong)(context.ProcessedBytesCount > 32 ? 0 : ((ulong)1 << 62)) | // is first
                (ulong)((ulong)TypeValue.Msg << 56);

            MemMap.ToULong32BytesLE(context.G, context.ThreefishContext.Key);
            ThreefishAlgorithm.Encrypt256(context.LastBlockBuffer, 0, context.ThreefishOutputBuffer, 0, t0, t1, context.ThreefishContext);

            for (int i = 0; i < 32; i++) context.G[i] = (byte)(context.ThreefishOutputBuffer[i] ^ context.LastBlockBuffer[i]);
        }
        
        public static void Output(Context context, byte[] outputBuffer, long outputOffset)
        {
            long copyOffset = outputOffset;
            long outputLengthInBytes = (long)context.Config.OutputLength / 8;
            long remaining = outputLengthInBytes;
            long stateSizeInBytes = (long)context.InternalStateSizeInBits / 8;
            ulong outputLengthInBlocks = (ulong)outputLengthInBytes / ((ulong)context.InternalStateSizeInBits / 8);
            ulong t0, t1;
            outputLengthInBlocks = outputLengthInBlocks == 0 ? 1 : outputLengthInBlocks;

            for (ulong i = 0; i < outputLengthInBlocks; i++)
            {
                t1 = ((ulong)1 << 63) | // final 
                     ((ulong)1 << 62) | // first
                     (ulong)((ulong)TypeValue.Out << 56);

                t0 = 8;

                MemMap.ToBytes1ULongLE(i, context.HashOutputCounter, 0);

                if (context.InternalStateSizeInBits == 256)
                {
                    MemMap.ToULong32BytesLE(context.G, context.ThreefishContext.Key);
                    ThreefishAlgorithm.Encrypt256(context.HashOutputCounter, 0, context.HashOutputBuffer, 0, t0, t1, context.ThreefishContext);
                }
                else if (context.InternalStateSizeInBits == 512)
                {
                    MemMap.ToULong64BytesLE(context.G, 0, context.ThreefishContext.Key, 0);
                    ThreefishAlgorithm.Encrypt512(context.HashOutputCounter, 0, context.HashOutputBuffer, 0, t0, t1, context.ThreefishContext);
                }
                else 
                {
                    MemMap.ToULong128BytesLE(context.G, 0, context.ThreefishContext.Key, 0);
                    ThreefishAlgorithm.Encrypt1024(context.HashOutputCounter, 0, context.HashOutputBuffer, 0, t0, t1, context.ThreefishContext);
                }

                for (int j = 0; j < stateSizeInBytes; j++) outputBuffer[j] ^= context.HashOutputCounter[j];

                long bytesToCopy = remaining > stateSizeInBytes ? stateSizeInBytes : remaining;
                MemCpy.Copy(context.HashOutputBuffer, 0, outputBuffer, outputOffset + copyOffset, bytesToCopy);
                remaining -= bytesToCopy; 
                copyOffset += bytesToCopy;
            }
        }

        /// <summary>
        /// Initialise Skein context that do not support tree version of algorithm
        /// </summary>
        public static Context SimpleInitialise(int outputLengthInBits, int internalStateSizeInBits)
        {
            int internalStateSizeInBytes = internalStateSizeInBits / 8;
            ConfigurationValue config = new ConfigurationValue();

            config.SchemaIdentifier = ConfigSchemaIdentifierSHA3;
            config.VersionNumber = ConfigVersionNumber;
            config.ReservedSetToZero_0 = 0;
            config.OutputLength = (ulong)outputLengthInBits;
            config.ReservedSetToZero_1 = new byte[13];

            Context context = new Context();

            context.InternalStateSizeInBits = internalStateSizeInBits;
            context.Config = config;
            context.LastBlockBuffer = new byte[internalStateSizeInBytes];
            context.ThreefishOutputBuffer = new byte[internalStateSizeInBytes];
            context.HashOutputCounter = new byte[internalStateSizeInBytes];
            context.HashOutputBuffer = new byte[internalStateSizeInBytes];
            context.ThreefishContext = ThreefishAlgorithm.Initialise(new byte[internalStateSizeInBytes]);
            context.G = new byte[internalStateSizeInBytes];
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

            MemMap.ToBytes1UIntLE(config.SchemaIdentifier, inputBlock, 0);
            MemMap.ToBytes1UShortLE(config.VersionNumber, inputBlock, 4);
            MemMap.ToBytes1ULongLE(config.OutputLength, inputBlock, 8);
            inputBlock[16] = config.TreeLeafSize;
            inputBlock[17] = config.TreeFanOut;
            inputBlock[18] = config.TreeMaxHeight;

            ThreefishAlgorithm.Context tfcontext = ThreefishAlgorithm.Initialise(keyAllZeros);

            t0 = (ulong)32;
            t1 = ((ulong)1 << 63) | // first
                   ((ulong)1 << 62) | // final
                   (ulong)TypeValue.Cfg << 56;


            if (context.InternalStateSizeInBits == 256)
            {
               ThreefishAlgorithm.Encrypt256(inputBlock, 0, context.G, 0, t0, t1, tfcontext);
            }
            else if (context.InternalStateSizeInBits == 512)
            {
                ThreefishAlgorithm.Encrypt512(inputBlock, 0, context.G, 0, t0, t1, tfcontext);
            }
            else 
            {
                ThreefishAlgorithm.Encrypt1024(inputBlock, 0, context.G, 0, t0, t1, tfcontext);
            }

            for (int i = 0; i < context.G.Length; i++)
            {
                context.G[i] ^= inputBlock[i];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void UBI512() {}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void UBI1024() {}
    }
}
