using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Tests.Core
{
    public class RepeatStream : Stream
    {
        public override bool CanRead => throw new NotImplementedException();

        public override bool CanSeek => throw new NotImplementedException();

        public override bool CanWrite => throw new NotImplementedException();

        public override long Length => throw new NotImplementedException();

        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        byte[] bytesToRepeat;
        int remaining;
        int cursor;

        public RepeatStream(byte[] bytesToRepeat, 
            int repeatCount,
            int randomGeneratorMinReadCount,
            int randomGeneratorMaxReadCount)
        {
            this.bytesToRepeat = new byte[bytesToRepeat.Length];
            this.remaining = this.bytesToRepeat.Length * repeatCount;
            this.cursor = 0;
            MemCpy.Copy(bytesToRepeat, this.bytesToRepeat);
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int loadedToBuf = 0;

            if (remaining > 0)
            {
                if (cursor == 0 && count > bytesToRepeat.Length && remaining >= count)
                {
                    int fullBufRepeat = count / bytesToRepeat.Length;
                    
                    for (int i = 0; i < fullBufRepeat; i++)
                    {
                        MemCpy.Copy(bytesToRepeat, 0, buffer, offset, bytesToRepeat.Length);
                        offset += bytesToRepeat.Length;
                        remaining -= bytesToRepeat.Length;
                        loadedToBuf += bytesToRepeat.Length;
                    }

                    Console.WriteLine("{0:X8}", remaining);

                    return loadedToBuf;
                }

                int canRead = bytesToRepeat.Length - cursor;
                canRead = canRead > remaining ? remaining : canRead;
                MemCpy.Copy(bytesToRepeat, cursor, buffer, offset, canRead);
                cursor += canRead;
                loadedToBuf += canRead;

                if (cursor == bytesToRepeat.Length)
                {
                    cursor = 0;
                }

                remaining-=canRead;
            }

            return loadedToBuf;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}
