using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11
{
    class NullCryptoTransform : ICryptoTransform
    {
        public bool CanReuseTransform
        {
            get
            {
                return true;
            }
        }

        public bool CanTransformMultipleBlocks
        {
            get
            {
                return true;
            }
        }

        public int InputBlockSize
        {
            get
            {
                return 1;
            }
        }

        public int OutputBlockSize
        {
            get
            {
                return 1;
            }
        }

        public void Dispose()
        {
            
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset, inputCount);

            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] identity = new byte[inputCount];
            Array.Copy(inputBuffer, inputOffset, identity, 0, inputCount);

            return identity;
        }
    }

    class NullStreamCipher : SymmetricAlgorithm
    {
        public NullStreamCipher() : base()
        {
            KeySizeValue = 0;
            IVValue = new byte[0];
            KeyValue = new byte[0];
            LegalKeySizesValue = new KeySizes[] { new KeySizes(0, int.MaxValue, 1) };
            LegalBlockSizesValue = new KeySizes[] { new KeySizes(0, int.MaxValue, 1) };
            Padding = PaddingMode.None;
        }


        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new NullCryptoTransform();
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new NullCryptoTransform();
        }

        public override void GenerateIV()
        {
            
        }

        public override void GenerateKey()
        {
            
        }
    }
}
