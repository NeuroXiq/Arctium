using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class NullStreamCipherAlgorithmTransform : ICryptoTransform
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
            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] result = new byte[inputCount];
            Buffer.BlockCopy(inputBuffer, inputOffset, result, 0, inputCount);

            return result;
        }
    }

    class NullStreamCipherAlgorithm : SymmetricAlgorithm
    {
        public NullStreamCipherAlgorithm()
        {
            base.BlockSizeValue = 1;
            base.FeedbackSizeValue = 1;
            base.IVValue = new byte[0];
            base.KeySizeValue = 0;
            base.KeyValue = new byte[0];
            base.LegalBlockSizesValue = new KeySizes[] { new KeySizes(0, int.MaxValue, 1) };
            base.LegalKeySizesValue = new KeySizes[] { new KeySizes(0, int.MaxValue, 1) };
            base.ModeValue = CipherMode.CBC;
            base.PaddingValue = PaddingMode.None;
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new NullStreamCipherAlgorithmTransform();
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new NullStreamCipherAlgorithmTransform();
        }

        public override void GenerateIV()
        {
            
        }

        public override void GenerateKey()
        {
            
        }
    }
}
