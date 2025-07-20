using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Interfaces;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.MAC
{
    public class Poly1305 : IProcessBytes
    {
        Poly1305Algorithm.Context context;
        BlockBufferWithCallback buffer;
        byte[] keyMaterial;

        public Poly1305(byte[] keyMaterial)
        {
            if (keyMaterial == null || keyMaterial.Length != 32) throw new ArgumentException("key != 32");
            context = Poly1305Algorithm.Initialize(keyMaterial);
            buffer = new BlockBufferWithCallback(2048, 16, ProcessFullBlocks); // buffer flush not work
            this.keyMaterial = keyMaterial;
        }

        public void Process(byte[] bytes) => Process(bytes, 0, bytes.Length);

        public void Process(byte[] bytes, long offset, long length) => buffer.Load(bytes, offset, length);

        public void Process(Stream stream)
        {
            (new SimpleBufferForStream()).MediateAllBytesInto(stream, this);
        }

        private void ProcessFullBlocks(byte[] buffer, long offset, long length)
        {
            Poly1305Algorithm.ProcessFullBlocks(context, buffer, offset, length);
        }

        public byte[] Final()
        {
            byte[] hash = new byte[16];
            byte[] notAlignedWithLast = new byte[16];
            long notAlignedLen;
            buffer.Flush(notAlignedWithLast, 0, out notAlignedLen);

            Poly1305Algorithm.ProcessLastBlock(context, notAlignedWithLast, 0, notAlignedLen, hash, 0);

            Reset();

            return hash;
        }


        public void Reset(byte[] key)
        {
            this.keyMaterial = key;
            Reset();
        }

        public void Reset()
        {
            Poly1305Algorithm.Reset(context, this.keyMaterial);
            buffer.Reset();
        }
    }
}
