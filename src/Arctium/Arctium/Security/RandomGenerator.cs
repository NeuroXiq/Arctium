namespace Arctium.Shared.Security
{
    public abstract class RandomGenerator
    {
        public abstract void Generate(byte[] buffer, long offset, long length);
    }
}
