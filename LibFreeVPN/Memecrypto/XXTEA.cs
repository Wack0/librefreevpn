/**********************************************************\
|                                                          |
| XXTEA.cs                                                 |
|                                                          |
| XXTEA encryption algorithm library for .NET.             |
|                                                          |
| Encryption Algorithm Authors:                            |
|      David J. Wheeler                                    |
|      Roger M. Needham                                    |
|                                                          |
| Code Author:  Ma Bingyao <mabingyao@gmail.com>           |
| LastModified: Mar 10, 2015                               |
|                                                          |
\**********************************************************/

using System;
using System.Text;

namespace LibFreeVPN.Memecrypto
{
    // XXTEA implementation with user-specified delta.
    // Used for many forks of sockshttp memecrypto.
    public sealed class XXTEA
    {
        private static readonly UTF8Encoding s_utf8 = new UTF8Encoding();

        private readonly uint m_delta;

        private static uint MX(uint sum, uint y, uint z, int p, uint e, uint[] k)
        {
            return (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
        }

        public XXTEA(uint delta = 0x9e3779b9u)
        {
            m_delta = delta;
        }

        public byte[] Encrypt(byte[] data, byte[] key)
        {
            if (data.Length == 0)
            {
                return data;
            }
            return ToByteArray(Encrypt(ToUIntArray(data, true), ToUIntArray(FixKey(key), false)), false);
        }

        public byte[] Encrypt(string data, byte[] key)
        {
            return Encrypt(s_utf8.GetBytes(data), key);
        }

        public byte[] Encrypt(byte[] data, string key)
        {
            return Encrypt(data, s_utf8.GetBytes(key));
        }

        public byte[] Encrypt(string data, string key)
        {
            return Encrypt(s_utf8.GetBytes(data), s_utf8.GetBytes(key));
        }

        public string EncryptToBase64String(byte[] data, byte[] key)
        {
            return Convert.ToBase64String(Encrypt(data, key));
        }

        public string EncryptToBase64String(string data, byte[] key)
        {
            return Convert.ToBase64String(Encrypt(data, key));
        }

        public string EncryptToBase64String(byte[] data, string key)
        {
            return Convert.ToBase64String(Encrypt(data, key));
        }

        public string EncryptToBase64String(string data, string key)
        {
            return Convert.ToBase64String(Encrypt(data, key));
        }

        public byte[] Decrypt(byte[] data, byte[] key)
        {
            if (data.Length == 0)
            {
                return data;
            }
            return ToByteArray(Decrypt(ToUIntArray(data, false), ToUIntArray(FixKey(key), false)), true);
        }

        public byte[] Decrypt(byte[] data, string key)
        {
            return Decrypt(data, s_utf8.GetBytes(key));
        }

        public byte[] DecryptBase64String(string data, byte[] key)
        {
            return Decrypt(Convert.FromBase64String(data), key);
        }

        public byte[] DecryptBase64String(string data, string key)
        {
            return Decrypt(Convert.FromBase64String(data), key);
        }

        public string DecryptToString(byte[] data, byte[] key)
        {
            return s_utf8.GetString(Decrypt(data, key));
        }

        public string DecryptToString(byte[] data, string key)
        {
            return s_utf8.GetString(Decrypt(data, key));
        }

        public string DecryptBase64StringToString(string data, byte[] key)
        {
            return s_utf8.GetString(DecryptBase64String(data, key));
        }

        public string DecryptBase64StringToString(string data, string key)
        {
            return s_utf8.GetString(DecryptBase64String(data, key));
        }

        private uint[] Encrypt(uint[] v, uint[] k)
        {
            int n = v.Length - 1;
            if (n < 1)
            {
                return v;
            }
            uint z = v[n], y, sum = 0, e;
            int p, q = 6 + 52 / (n + 1);
            unchecked
            {
                while (0 < q--)
                {
                    sum += m_delta;
                    e = sum >> 2 & 3;
                    for (p = 0; p < n; p++)
                    {
                        y = v[p + 1];
                        z = v[p] += MX(sum, y, z, p, e, k);
                    }
                    y = v[0];
                    z = v[n] += MX(sum, y, z, p, e, k);
                }
            }
            return v;
        }

        private uint[] Decrypt(uint[] v, uint[] k)
        {
            int n = v.Length - 1;
            if (n < 1)
            {
                return v;
            }
            uint z, y = v[0], sum, e;
            int p, q = 6 + 52 / (n + 1);
            unchecked
            {
                sum = (uint)(q * m_delta);
                while (sum != 0)
                {
                    e = sum >> 2 & 3;
                    for (p = n; p > 0; p--)
                    {
                        z = v[p - 1];
                        y = v[p] -= MX(sum, y, z, p, e, k);
                    }
                    z = v[n];
                    y = v[0] -= MX(sum, y, z, p, e, k);
                    sum -= m_delta;
                }
            }
            return v;
        }

        private static byte[] FixKey(byte[] key)
        {
            if (key.Length == 16) return key;
            byte[] fixedkey = new byte[16];
            if (key.Length < 16)
            {
                Buffer.BlockCopy(key, 0, fixedkey, 0, key.Length);
            }
            else
            {
                Buffer.BlockCopy(key, 0, fixedkey, 0, 16);
            }
            return fixedkey;
        }

        private static uint[] ToUIntArray(byte[] data, bool includeLength)
        {
            int length = data.Length;
            int n = (((length & 3) == 0) ? (length >> 2) : ((length >> 2) + 1));
            uint[] result;
            if (includeLength)
            {
                result = new uint[n + 1];
                result[n] = (uint)length;
            }
            else
            {
                result = new uint[n];
            }
            for (int i = 0; i < length; i++)
            {
                result[i >> 2] |= (uint)data[i] << ((i & 3) << 3);
            }
            return result;
        }

        private static byte[] ToByteArray(uint[] data, bool includeLength)
        {
            int n = data.Length << 2;
            if (includeLength)
            {
                int m = (int)data[data.Length - 1];
                n -= 4;
                if ((m < n - 3) || (m > n))
                {
                    return null;
                }
                n = m;
            }
            byte[] result = new byte[n];
            for (int i = 0; i < n; i++)
            {
                result[i] = (byte)(data[i >> 2] >> ((i & 3) << 3));
            }
            return result;
        }
    }
}
