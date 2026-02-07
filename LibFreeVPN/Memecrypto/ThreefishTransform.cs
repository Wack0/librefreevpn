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

Bug fixes:
Copyright (c) 2015 Pavel Kovalenko
Same licence, etc. applies.
*/

using System;
using System.Security.Cryptography;

namespace LibFreeVPN.Memecrypto
{
    public enum ThreefishTransformMode {Encrypt, Decrypt}

    public class ThreefishTransform : ICryptoTransform
    {
        private delegate int TransformFunc(byte[] input, int inputOffset, int inputCount,
            byte[] output, int outputOffset);

        private readonly ThreefishCipher cipher;
        private readonly TransformFunc transformFunc;
        private readonly ThreefishTransformMode transformMode;
        private readonly CipherMode cipherMode;
        private readonly PaddingMode paddingMode;
        private readonly int feedbackBytes;
        private readonly int cipherBytes;
        private readonly int cipherWords;
        private readonly ulong[] block;
        private readonly ulong[] tempBlock;
        private readonly ulong[] iv;
        private readonly byte[] depadBuffer;
        private bool depadBufferFilled = false;
        // Used when in a stream ciphering mode
        private readonly byte[] streamBytes;
        private int usedStreamBytes;

        internal ThreefishTransform(byte[] key, byte[] iv, int feedbackSize, ThreefishTransformMode transformMode,
            CipherMode cipherMode, PaddingMode paddingMode)
        {
            this.transformMode = transformMode;
            this.cipherMode = cipherMode;
            this.paddingMode = paddingMode;
            cipherBytes = key.Length;
            cipherWords = key.Length/8;
            feedbackBytes = feedbackSize/8;
            // Allocate working blocks now so that we don't have to allocate them
            // each time Transform(Final)Block is called
            block = new ulong[cipherWords];
            tempBlock = new ulong[cipherWords];
            streamBytes = new byte[cipherBytes];
            depadBuffer = new byte[cipherBytes];
            this.iv = new ulong[cipherWords];
            GetBytes(iv, 0, this.iv, cipherBytes);
            switch (OutputBlockSize)
            {
            case 256/8: cipher = new Threefish256(); break;
            case 512/8: cipher = new Threefish512(); break;
            case 1024/8: cipher = new Threefish1024(); break;
            default: throw new CryptographicException("Unsupported key/block size.");
            }
            bool e = transformMode==ThreefishTransformMode.Encrypt;
            switch (cipherMode)
            {
            case CipherMode.ECB:
                transformFunc = e ? EcbEncrypt : new TransformFunc(EcbDecrypt);
                break;
            case CipherMode.CBC:
                transformFunc = e ? CbcEncrypt : new TransformFunc(CbcDecrypt);
                break;
            case CipherMode.OFB:
                transformFunc = OfbApplyStream;
                break;
            case CipherMode.CFB:
                transformFunc = e ? CfbEncrypt : new TransformFunc(CfbDecrypt);
                break;
            default:
                throw new CryptographicException("Unsupported cipher mode.");
            }
            var keyWords = new ulong[cipherWords];
            GetBytes(key, 0, keyWords, cipherBytes);
            cipher.SetKey(keyWords);
            InitializeBlocks();
        }

        public void SetTweak(ulong[] tweak)
        {
            if (tweak.Length!=2)
                throw new ArgumentException("Tweak must be an array of two unsigned 64-bit integers.");
            InternalSetTweak(tweak);
        }

        public void InternalSetTweak(ulong[] tweak) { cipher.SetTweak(tweak); }

        // (Re)initializes the blocks for encryption
        private void InitializeBlocks()
        {
            switch (cipherMode)
            {
            case CipherMode.ECB:
            case CipherMode.CBC:
                // Clear the working block
                for (int i = 0; i<cipherWords; i++)
                    block[i] = 0;
                break;
            case CipherMode.OFB:
                // Copy the IV to the working block
                for (int i = 0; i<cipherWords; i++)
                    block[i] = iv[i];
                break;
            case CipherMode.CFB:
                // Copy IV to cipher stream bytes
                PutBytes(iv, streamBytes, 0, cipherBytes);
                break;
            }
            depadBufferFilled = false;
            usedStreamBytes = cipherBytes;
        }

        #region Utils

        private static ulong GetUInt64(byte[] buf, int offset)
        {
            ulong v = buf[offset];
            v |= (ulong)buf[offset+1]<<8;
            v |= (ulong)buf[offset+2]<<16;
            v |= (ulong)buf[offset+3]<<24;
            v |= (ulong)buf[offset+4]<<32;
            v |= (ulong)buf[offset+5]<<40;
            v |= (ulong)buf[offset+6]<<48;
            v |= (ulong)buf[offset+7]<<56;
            return v;
        }

        private static void PutUInt64(byte[] buf, int offset, ulong v)
        {
            buf[offset] = (byte)(v & 0xff);
            buf[offset+1] = (byte)(v>>8 & 0xff);
            buf[offset+2] = (byte)(v>>16 & 0xff);
            buf[offset+3] = (byte)(v>>24 & 0xff);
            buf[offset+4] = (byte)(v>>32 & 0xff);
            buf[offset+5] = (byte)(v>>40 & 0xff);
            buf[offset+6] = (byte)(v>>48 & 0xff);
            buf[offset+7] = (byte)(v>>56);
        }

        private static void GetBytes(byte[] input, int offset, ulong[] output, int byteCount)
        {
            for (int i = 0; i<byteCount; i += 8)
                output[i/8] = GetUInt64(input, i+offset);
        }

        private static void PutBytes(ulong[] input, byte[] output, int offset, int byteCount)
        {
            for (int i = 0; i<byteCount; i += 8)
                PutUInt64(output, i+offset, input[i/8]);
        }

        #endregion

        #region ModeTransformFunctions

        // ECB mode encryption
        private int EcbEncrypt(byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            if (inputCount<cipherBytes)
                return 0;
            GetBytes(input, inputOffset, block, cipherBytes);
            cipher.Encrypt(block, block);
            PutBytes(block, output, outputOffset, cipherBytes);
            return cipherBytes;
        }

        // ECB mode decryption
        private int EcbDecrypt(byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            if (inputCount<cipherBytes)
                return 0;
            GetBytes(input, inputOffset, block, cipherBytes);
            cipher.Decrypt(block, block);
            PutBytes(block, output, outputOffset, cipherBytes);
            return cipherBytes;
        }

        // CBC mode encryption
        private int CbcEncrypt(byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            if (inputCount<cipherBytes)
                return 0;
            GetBytes(input, inputOffset, block, cipherBytes);
            // Apply the IV
            for (int i = 0; i<cipherWords; i++)
                block[i] ^= iv[i];
            cipher.Encrypt(block, block);
            // Copy the output to the IV
            for (int i = 0; i<cipherWords; i++)
                iv[i] = block[i];
            PutBytes(block, output, outputOffset, cipherBytes);
            return cipherBytes;
        }

        // CBC mode encryption
        private int CbcDecrypt(byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            if (inputCount<cipherBytes)
                return 0;
            GetBytes(input, inputOffset, block, cipherBytes);
            // Copy the block to the temp block for later (wink wink)
            for (int i = 0; i<cipherWords; i++)
                tempBlock[i] = block[i];
            cipher.Decrypt(block, block);
            // Apply the IV and copy temp block
            // to IV
            for (int i = 0; i<cipherWords; i++)
            {
                block[i] ^= iv[i];
                iv[i] = tempBlock[i];
            }
            PutBytes(block, output, outputOffset, cipherBytes);
            return cipherBytes;
        }

        // OFB mode encryption/decryption
        private int OfbApplyStream(byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            // Input length doesn't matter in OFB, just encrypt
            // as much as we can
            for (int i = 0; i<inputCount; i++)
            {
                // Generate new stream bytes if we've used
                // them all up
                if (usedStreamBytes>=feedbackBytes)
                {
                    cipher.Encrypt(block, block);
                    PutBytes(block, streamBytes, 0, feedbackBytes);
                    usedStreamBytes = 0;
                }
                // XOR input byte with stream byte, output it
                output[outputOffset+i] = (byte)(input[inputOffset+i] ^ streamBytes[usedStreamBytes]);
                usedStreamBytes++;
            }
            // Return bytes done
            return inputCount;
        }

        // CFB mode encryption
        private int CfbEncrypt(byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            for (int i = 0; i<inputCount; i++)
            {
                // Generate new stream bytes if we've used
                // them all up
                if (usedStreamBytes>=feedbackBytes)
                {
                    // Copy cipher stream bytes to working block
                    // (this is the feedback)
                    GetBytes(streamBytes, 0, block, feedbackBytes);
                    // Process
                    cipher.Encrypt(block, block);
                    // Put back
                    PutBytes(block, streamBytes, 0, feedbackBytes);
                    // Reset for next time
                    usedStreamBytes = 0;
                }
                // XOR input byte with stream byte
                var b = (byte)(input[inputOffset+i] ^ streamBytes[usedStreamBytes]);
                // Output cipher byte
                output[outputOffset+i] = b;
                // Put cipher byte into stream bytes for the feedback
                streamBytes[usedStreamBytes] = b;
                usedStreamBytes++;
            }
            // Return bytes done
            return inputCount;
        }

        // CFB mode decryption
        private int CfbDecrypt(byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            for (int i = 0; i<inputCount; i++)
            {
                // Generate new stream bytes if we've used
                // them all up
                if (usedStreamBytes>=feedbackBytes)
                {
                    // Copy cipher stream bytes to working block
                    // (this is the feedback)
                    GetBytes(streamBytes, 0, block, feedbackBytes);
                    // Process
                    cipher.Encrypt(block, block);
                    // Put back
                    PutBytes(block, streamBytes, 0, feedbackBytes);
                    // Reset for next time
                    usedStreamBytes = 0;
                }
                // Get ciphertext byte
                byte b = input[inputOffset+i];
                // XOR input byte with stream byte, output plaintext
                output[outputOffset+i] = (byte)(b ^ streamBytes[usedStreamBytes]);
                // Put ciphertext byte into stream bytes for the feedback
                streamBytes[usedStreamBytes] = b;
                usedStreamBytes++;
            }
            // Return bytes done
            return inputCount;
        }

        #endregion

        #region ICryptoTransform Members

        public bool CanReuseTransform
        {
            get { return true; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        public int InputBlockSize
        {
            get { return cipherBytes; }
        }

        public int OutputBlockSize
        {
            get { return cipherBytes; }
        }

        private void PadBlock(byte[] input, int inputOffset, int alreadyFilled)
        {
            // Apply the type of padding we're using
            switch (paddingMode)
            {
            case PaddingMode.None:
                break;
            case PaddingMode.Zeros:
                // Fill with zeros
                for (int i = alreadyFilled; i<cipherBytes; i++)
                    input[i+inputOffset] = 0;
                break;
            case PaddingMode.PKCS7:
                // Fill each byte value with the number of
                // bytes padded
                for (int i = alreadyFilled; i<cipherBytes; i++)
                    input[i+inputOffset] = (byte)(cipherBytes-alreadyFilled);
                break;
            case PaddingMode.ANSIX923:
                // fill with zeros, set last byte
                // to number of bytes padded
                for (int i = alreadyFilled; i<cipherBytes; i++)
                {
                    input[i+inputOffset] = 0;
                    // If its the last byte, set to number of bytes padded
                    if (i==cipherBytes-1)
                        input[i+inputOffset] = (byte)(cipherBytes-alreadyFilled);
                }
                break;
            case PaddingMode.ISO10126:
                // Fill remaining bytes with random values before the number of bytes padded
                if (alreadyFilled<cipherBytes)
                {
                    var randBytes = new byte[cipherBytes-alreadyFilled];
                    new RNGCryptoServiceProvider().GetBytes(randBytes);
                    randBytes[randBytes.Length-1] = (byte)randBytes.Length;
                    for (int i = alreadyFilled; i<cipherBytes; i++)
                        input[i+inputOffset] = randBytes[i-alreadyFilled];
                }
                break;
            }
        }

        private byte[] DepadBlock(byte[] input)
        {
            var output = input;
            int padSize;
            switch (paddingMode)
            {
            case PaddingMode.None:
                break;
            case PaddingMode.Zeros:
                break;
            case PaddingMode.PKCS7:
                padSize = input[input.Length-1];
                if (padSize>input.Length || padSize>InputBlockSize || padSize<=0)
                    throw new CryptographicException("PKCS7 invalid padding");
                for (int i = 1; i<=padSize; i++)
                {
                    if (input[input.Length-i]!=padSize)
                        throw new CryptographicException("PKCS7 invalid padding");
                }
                output = new byte[input.Length-padSize];
                Buffer.BlockCopy(input, 0, output, 0, output.Length);
                break;
            case PaddingMode.ANSIX923:
                padSize = input[input.Length-1];
                if (padSize>input.Length || padSize>InputBlockSize || padSize<=0)
                    throw new CryptographicException("ANSIX923 invalid padding");
                for (int i = 2; i<=padSize; i++)
                    if (output[input.Length-i]!=0)
                        throw new CryptographicException("ANSIX923 invalid padding");
                output = new byte[input.Length-padSize];
                Buffer.BlockCopy(input, 0, output, 0, output.Length);
                break;
            case PaddingMode.ISO10126:
                padSize = input[input.Length-1];
                if (padSize>input.Length || padSize>InputBlockSize || padSize<=0)
                    throw new CryptographicException("ISO10126 invalid padding");
                output = new byte[input.Length-padSize];
                Buffer.BlockCopy(input, 0, output, 0, output.Length);
                break;
            }
            return output;
        }

        private int Transform(byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
        {
            int done, totalDone = 0;
            do
            {
                done = transformFunc(input, inputOffset+totalDone, inputCount-totalDone, output,
                    outputOffset+totalDone);
                totalDone += done;
            } while (done==cipherBytes);
            return totalDone;
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
            int outputOffset)
        {
            if ((inputCount & (cipherBytes-1))!=0)
                throw new CryptographicException("inputCount must be divisible by the block size.");
            int done = 0;
            if (transformMode==ThreefishTransformMode.Encrypt ||
                paddingMode==PaddingMode.Zeros || paddingMode==PaddingMode.None)
            {
                done = Transform(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            }
            else
            {
                int inputToProcess = inputCount-cipherBytes;
                if (depadBufferFilled)
                {
                    done = Transform(depadBuffer, 0, cipherBytes, outputBuffer, outputOffset);
                    outputOffset += cipherBytes;
                }
                else
                    depadBufferFilled = true;
                Buffer.BlockCopy(inputBuffer, inputOffset+inputToProcess, depadBuffer, 0, cipherBytes);
                done += Transform(inputBuffer, inputOffset+done, inputToProcess-done, outputBuffer, outputOffset+done);
            }
            return done;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] output;
            // Do the padding and the final transform if there's any data left
            if (transformMode==ThreefishTransformMode.Encrypt)
            {
                if (inputCount%cipherBytes!=0 && paddingMode==PaddingMode.None)
                    throw new CryptographicException("inputCount must be divisible by the block size.");
                output = new byte[inputCount];
                int done = Transform(inputBuffer, inputOffset, inputCount, output, 0);
                if ((done<inputCount || inputCount%cipherBytes==0) && paddingMode!=PaddingMode.None)
                {
                    // Resize output buffer to be evenly divisible by the block size
                    int outputSize = inputCount+(cipherBytes-(inputCount%cipherBytes));
                    Array.Resize(ref output, outputSize);
                    int remaining = inputCount-done;
                    // Copy remaining bytes over to the output
                    for (int i = 0; i<remaining; i++)
                        output[i+done] = inputBuffer[inputOffset+done+i];
                    PadBlock(output, done, remaining);
                    Transform(output, done, cipherBytes, output, done);
                }
            }
            else // decrypt
            {
                if (inputCount%cipherBytes!=0)
                    throw new CryptographicException("inputCount must be divisible by the block size.");
                if (!depadBufferFilled)
                {
                    output = new byte[inputCount];
                    Transform(inputBuffer, inputOffset, inputCount, output, 0);
                }
                else
                {
                    // XXX nitrocaster: could be optimized: copy to output and perform in-place decryption
                    var buf = new byte[cipherBytes+inputCount];
                    Buffer.BlockCopy(depadBuffer, 0, buf, 0, cipherBytes);
                    Buffer.BlockCopy(inputBuffer, inputOffset, buf, cipherBytes, inputCount);
                    output = new byte[cipherBytes+inputCount];
                    Transform(buf, 0, buf.Length, output, 0);
                }
                output = DepadBlock(output);
            }
            // Reinitialize the cipher
            InitializeBlocks();
            return output;
        }

        #endregion

        #region IDisposable Members

        public void Dispose() { Dispose(true); }

        private void Dispose(bool disposing)
        {
            if (!disposing)
                return;
            // reset fields with sensitive data
            cipher.Clear();
            Array.Clear(block, 0, block.Length);
            Array.Clear(tempBlock, 0, tempBlock.Length);
            Array.Clear(iv, 0, iv.Length);
            Array.Clear(depadBuffer, 0, depadBuffer.Length);
            Array.Clear(streamBytes, 0, streamBytes.Length);
        }

        #endregion
    }
}
