using System.Runtime.CompilerServices;

namespace Arctium.Shared.Helpers.Binary
{
    public static class BinOps
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ROR(uint v, int r)
        {
            return (v >> r) | (v << (32 - r));
        }
    }
}
