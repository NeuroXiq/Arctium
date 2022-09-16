using Arctium.Cryptography.HashFunctions.Hashes.Algorithms;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Cryptography.HashFunctions.MAC
{
    internal class Poly1305 : IProcessBytes
    {
        Poly1305Algorithm.Context context;
        byte[] keyMaterial;

        public Poly1305(byte[] keyMaterial)
        {
            context = Poly1305Algorithm.Initialize(keyMaterial);
            this.keyMaterial = keyMaterial;
        }

        public void Process(byte[] bytes) => Process(bytes, 0, bytes.Length);

        public void Process(byte[] bytes, long offset, long length)
        {
            throw new NotImplementedException();
        }

        public void Process(Stream stream)
        {
            (new SimpleBufferForStream()).MediateAllBytesInto(stream, this);
        }

        public byte[] Final()
        {
            //Poly1305Algorithm.ProcessLastBlock(
            throw new NotImplementedException();
            Reset();
        }


        public void Reset()
        {
            Poly1305Algorithm.Reset(context, keyMaterial);
        }
    }
}
