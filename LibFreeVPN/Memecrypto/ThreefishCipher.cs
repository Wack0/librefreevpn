/*
Copyright (c) 2010 Alberto Fajardo

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

using System;

namespace LibFreeVPN.Memecrypto
{
    internal abstract class ThreefishCipher
    {
        protected const ulong KeyScheduleConst = 0x1BD11BDAA9FC1A22;
        protected const int ExpandedTweakSize = 3;
        protected ulong[] ExpandedKey;
        protected ulong[] ExpandedTweak;

        protected ThreefishCipher()
        { ExpandedTweak = new ulong[ExpandedTweakSize]; }

        protected static ulong RotateLeft64(ulong v, int b)
        { return v<<b | v>>(64-b); }

        protected static ulong RotateRight64(ulong v, int b)
        { return v>>b | v<<(64-b); }

        protected static void Mix(ref ulong a, ref ulong b, int r)
        {
            a += b;
            b = RotateLeft64(b, r) ^ a;
        }

        protected static void Mix(ref ulong a, ref ulong b, int r, ulong k0, ulong k1)
        {
            b += k1;
            a += b+k0;
            b = RotateLeft64(b, r) ^ a;
        }

        protected static void UnMix(ref ulong a, ref ulong b, int r)
        {
            b = RotateRight64(b ^ a, r);
            a -= b;
        }

        protected static void UnMix(ref ulong a, ref ulong b, int r, ulong k0, ulong k1)
        {
            b = RotateRight64(b ^ a, r);
            a -= b+k0;
            b -= k1;
        }

        public void SetTweak(ulong[] tweak)
        {
            ExpandedTweak[0] = tweak[0];
            ExpandedTweak[1] = tweak[1];
            ExpandedTweak[2] = tweak[0] ^ tweak[1];
        }

        public void SetKey(ulong[] key)
        {
            ulong parity = KeyScheduleConst;
            for (int i = 0; i<ExpandedKey.Length-1; i++)
            {
                ExpandedKey[i] = key[i];
                parity ^= key[i];
            }
            ExpandedKey[ExpandedKey.Length-1] = parity;
        }

        public void Clear()
        {
            Array.Clear(ExpandedKey, 0, ExpandedKey.Length);
            ExpandedKey[ExpandedKey.Length-1] = KeyScheduleConst;
            Array.Clear(ExpandedTweak, 0, ExpandedTweak.Length);
        }

        public static ThreefishCipher CreateCipher(int stateSize)
        {
            switch (stateSize)
            {
            case 256: return new Threefish256();
            case 512: return new Threefish512();
            case 1024: return new Threefish1024();
            default: return null;
            }
        }

        public abstract void Encrypt(ulong[] input, ulong[] output);
        public abstract void Decrypt(ulong[] input, ulong[] output);
    }
}
