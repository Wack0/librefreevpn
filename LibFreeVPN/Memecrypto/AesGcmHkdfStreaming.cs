using HkdfStandard;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Security.Cryptography;

// Port of AesGcmHkdfStreaming from Tink (decrypt only, with entire byte array)
namespace LibFreeVPN.Memecrypto
{
    public class AesGcmHkdfStreaming
    {
        private const int NONCE_LENGTH = 12;
        private const int NONCE_PREFIX_LENGTH = 7;
        private const int TAG_LENGTH = 16;

        private readonly HashAlgorithmName m_HkdfAlgo;
        private readonly int m_KeySize;
        private readonly int m_CiphertextChunkSize;
        private readonly int m_FirstChunkOffset;

        private int HeaderLength => 1 + m_KeySize + NONCE_PREFIX_LENGTH;

        public AesGcmHkdfStreaming(HashAlgorithmName hkdfAlgo, int keySize, int ciphertextChunkSize, int firstChunkOffset = 0)
        {
            if (keySize != 0x10 && keySize != 0x20) throw new ArgumentOutOfRangeException(nameof(keySize));

            m_HkdfAlgo = hkdfAlgo;
            m_KeySize = keySize;
            m_CiphertextChunkSize = ciphertextChunkSize;
            m_FirstChunkOffset = firstChunkOffset;

            if (ciphertextChunkSize < (firstChunkOffset + HeaderLength + TAG_LENGTH)) throw new ArgumentOutOfRangeException(nameof(ciphertextChunkSize));
        }

        public byte[] Decrypt(byte[] kek, byte[] info, byte[] ciphertext)
        {
            if (kek.Length < 0x10 || kek.Length < m_KeySize) throw new ArgumentOutOfRangeException(nameof(kek));

            // Starts with following header:
            // byte headerLength = HeaderLength
            // byte salt[m_KeySize]
            // byte noncePrefix[NONCE_PREFIX_LENGTH]
            if (ciphertext[0] != HeaderLength) throw new InvalidDataException();
            var salt = new byte[m_KeySize];
            var noncePrefix = new byte[NONCE_PREFIX_LENGTH];
            Buffer.BlockCopy(ciphertext, 1, salt, 0, m_KeySize);
            Buffer.BlockCopy(ciphertext, 1 + m_KeySize, noncePrefix, 0, NONCE_PREFIX_LENGTH);

            // calculate the actual AES key HKDF-HMAC-algo(key = kek, salt = salt, info = info, length = keySize)
            byte[] key = Hkdf.DeriveKey(m_HkdfAlgo, kek, m_KeySize, salt, info);


            // There follows chunks of ciphertext.
            int offset = HeaderLength + m_FirstChunkOffset;
            int chunkIndex = 0;
            int plainLen = 0;

            var nonce = new byte[NONCE_LENGTH];
            Buffer.BlockCopy(noncePrefix, 0, nonce, 0, NONCE_PREFIX_LENGTH);

            var ret = new byte[ciphertext.Length];

            for (; offset < ciphertext.Length; chunkIndex++)
            {
                bool last = (ciphertext.Length - offset) <= m_CiphertextChunkSize;
                int chunkLen = Math.Min(m_CiphertextChunkSize, ciphertext.Length - offset);
                if (offset == (HeaderLength + m_FirstChunkOffset)) chunkLen = (m_CiphertextChunkSize - offset);
                // Calculate nonce for this segment
                // prefix followed by uint32_big chunkIndex followed by bool last
                nonce[NONCE_PREFIX_LENGTH + 0] = (byte)(chunkIndex >> 24);
                nonce[NONCE_PREFIX_LENGTH + 1] = (byte)(chunkIndex >> 16);
                nonce[NONCE_PREFIX_LENGTH + 2] = (byte)(chunkIndex >> 8);
                nonce[NONCE_PREFIX_LENGTH + 3] = (byte)(chunkIndex >> 0);
                nonce[NONCE_PREFIX_LENGTH + 4] = (byte)(last ? 1 : 0);

                GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
                AeadParameters parameters = new AeadParameters(new KeyParameter(key), TAG_LENGTH * 8, nonce, null);
                cipher.Init(false, parameters);
                byte[] plainBytes = new byte[cipher.GetOutputSize(chunkLen)];
                int retLen = cipher.ProcessBytes(ciphertext, offset, chunkLen, plainBytes, 0);
                cipher.DoFinal(plainBytes, retLen);

                //retLen = plainBytes.Length;

                //while (retLen != 0 && plainBytes[retLen - 1] == 0) retLen--;

                offset += chunkLen;
                Buffer.BlockCopy(plainBytes, 0, ret, plainLen, plainBytes.Length);
                plainLen += plainBytes.Length;
            }

            var retTrim = new byte[plainLen];
            Buffer.BlockCopy(ret, 0, retTrim, 0, plainLen);
            return retTrim;
        }
    }
}
