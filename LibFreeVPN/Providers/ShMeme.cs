using HkdfStandard;
using LibFreeVPN.Memecrypto;
using LibFreeVPN.ProviderHelpers;
using LibFreeVPN.Servers;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// Android apps - SocksHttp forks.
// Uses a native lib to do memecrypto.
// Memecrypto used: AES-128-CBC + XXTEA, and threefish + AES-128-CBC
// for the former, key is generated using SHA256 by constant
// for the latter, key is generated using KDF by constant
// Additionally, for some fields, substitution cipher is used (per bit), followed by XXTEA + AES-256-CBC (with key generated using PBKDF2 by constant)
namespace LibFreeVPN.Providers.SocksHttp.ShMeme
{

    public abstract class ProviderBase<TParser> : VPNProviderHttpGetBase<TParser>
        where TParser : SocksHttpRenzParser<TParser>, new()
    {
        public override bool HasProtocol(ServerProtocol protocol)
        {
            return protocol == ServerProtocol.OpenVPN || protocol == ServerProtocol.V2Ray || protocol == ServerProtocol.SSH;
        }
    }

    public sealed class ShMemeMhr : ProviderBase<ShMemeMhr.Parser>
    {
        public sealed class Parser : SocksHttpRenzParser<Parser>
        {
            private static readonly byte[] s_OuterKeyDerivation =
            {
                  0x98, 0xEE, 0xFC, 0xE9, 0x5F, 0x00, 0x92, 0x3D, 0x10, 0x45,
                  0xC8, 0x71, 0x14, 0x2E, 0x33, 0x2B, 0x63, 0xEB, 0x86, 0xA3,
                  0xE7, 0x32, 0xE5, 0x8B, 0x0C, 0xB8, 0xE6, 0x59, 0x58, 0xDE,
                  0xF7, 0xB7
            };

            private static readonly byte[] s_OuterIV =
            {
                  0x9A, 0xA6, 0x53, 0x7C, 0x94, 0x05, 0x7F, 0x7F, 0x33, 0x8A,
                  0x62, 0x7C, 0x00, 0xFF, 0x83, 0x38
            };


            private static readonly byte[] s_InnerSalt =
            {
                  0x37, 0xD7, 0x9B, 0x96, 0x80, 0xF6, 0x4E, 0xE1, 0x87, 0x21,
                  0xFB, 0xEF, 0x00, 0xE4, 0x8B, 0x37, 0xA4, 0x1B, 0x54, 0x4D,
                  0x4C, 0x00, 0xBB, 0xA7, 0x8F, 0xF3, 0xA5, 0xF7, 0x11, 0xDD,
                  0xEB, 0x52
            };


            protected override byte[] OuterKeyDerivation => s_OuterKeyDerivation;

            protected override byte[] OuterIV => s_OuterIV;

            protected override byte[] InnerSalt => s_InnerSalt;
        }
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5taHJ0dW5uZWwudmlw";

        public override string SampleVersion => "18";

        protected override string RequestUri => Encoding.ASCII.FromBase64String("aHR0cHM6Ly9taHJicm8ueHl6L2FwaS9hcHA/anNvbj04ZjczYjFiMjQ0YWVmOThjZDljNg==");
    }

    public sealed class ShMemeTrp : VPNProviderGithubRepoFileBase<ShMemeTrp.Parser>
    {
        public sealed class Parser : SocksHttpRenzParser2<Parser>
        {
            private static readonly byte[] s_OuterKeyDerivation =
            {
                0x4c, 0x7a, 0x28, 0x3f, 0x2b, 0x5a, 0x21, 0x6a, 0x39, 0x2e, 0x70, 0x24, 0x46, 0x40, 0x4e, 0x3e
            };

            private static readonly byte[] s_OuterIV = new byte[0x10]; // zero-filled


            protected override byte[] OuterKeyDerivation => s_OuterKeyDerivation;

            protected override byte[] OuterIV => s_OuterIV;

            protected override byte[] InnerSalt => s_OuterKeyDerivation; // unused

            protected override string ProtocolTypeV2ray => "4";
            protected override uint TeaDelta => 0x9E3779B9;

            protected override string OvpnConfTemplate => Encoding.ASCII.FromBase64String(
                "Y2xpZW50CmRldiB0dW4KcmVtb3RlIDAuMC4wLjAgMTE5NApub2JpbmQKY2lwaGVyIG5vbmUKYXV0" +
                "aCBub25lCmF1dGgtdXNlci1wYXNzCiNwaW5nLXRpbWVyLXJlbQpyZWRpcmVjdC1nYXRld2F5IGRl" +
                "ZjEKc2V0ZW52IENMSUVOVF9DRVJUIDAKdmVyYiAzCjxjYT4KLS0tLS1CRUdJTiBDRVJUSUZJQ0FU" +
                "RS0tLS0tCk1JSUNNVENDQVpxZ0F3SUJBZ0lVQWFRQkFwTVMyZFlCcVlQY0EzUGE3Y2pqdzdjd0RR" +
                "WUpLb1pJaHZjTkFRRUwKQlFBd0R6RU5NQXNHQTFVRUF3d0VTMjlpV2pBZUZ3MHlNREEzTWpJeU1q" +
                "SXpNek5hRncwek1EQTNNakF5TWpJegpNek5hTUE4eERUQUxCZ05WQkFNTUJFdHZZbG93Z1o4d0RR" +
                "WUpLb1pJaHZjTkFRRUJCUUFEZ1kwQU1JR0pBb0dCCkFNRjQ2VVZpMk81cFpwZGRPUHl6VTJFeUly" +
                "cjhOcnBYcXM4QmxZaFVqeE9jQ3JrTWpGdTJHOWhrN1FJWjRxTzAKR1dWWnBQaFlrNXFXaytMeENz" +
                "cnlyU29lMGE1SGFxSXllOEJGSm1YVjBrK08vM2U2azA2VUdOaWkzZ3hCV1FwRgo3ci8yQ3lRTHVz" +
                "OU9TcFFQWXN6QnlCdnRrd2lCQW8vVjk4amRwbStFVnU2dEFnTUJBQUdqZ1lrd2dZWXdIUVlEClZS" +
                "ME9CQllFRkdSSk1tLytabUx4VjAyN2thaGR2U1krVWFUU01Fb0dBMVVkSXdSRE1FR0FGR1JKTW0v" +
                "K1ptTHgKVjAyN2thaGR2U1krVWFUU29ST2tFVEFQTVEwd0N3WURWUVFEREFSTGIySmFnaFFCcEFF" +
                "Q2t4TFoxZ0dwZzl3RApjOXJ0eU9QRHR6QU1CZ05WSFJNRUJUQURBUUgvTUFzR0ExVWREd1FFQXdJ" +
                "QkJqQU5CZ2txaGtpRzl3MEJBUXNGCkFBT0JnUUMwZjh3YjVoeUVPRUVYNjRsOFFDTnB5ZC9XTGpv" +
                "ZUU1YkUreG5JY0tFK1hwRW9EUlp3dWdMb3lRZGMKSEthM2FSSE5xS3BSN0g2OTZYSlJlbzQrcG9j" +
                "RGV5ajdyQVRiTzVkWm1TTU5tTXpic2pRZVh1eDBYandtWklIdQplREtNZWZEaTBaZmlabW5VMm5q" +
                "bVRuY3laS3h2MThJa2p3czBNeWM4UHRBeHkycWRjQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0t" +
                "LS0KPC9jYT4="
            );

            protected override string DecryptOuter(string ciphertext)
            {
                // XXTEA first
                return Encoding.UTF8.GetString(DecryptAes(XXTEA.DecryptBase64String(ciphertext, OuterKey), OuterKey, OuterIV));
            }

            protected override string DecryptInner(string jsonKey, string ciphertext)
            {
                if (jsonKey == ServerNameKey || jsonKey == PortKey || jsonKey == CountryNameKey || jsonKey == OvpnKey || jsonKey == OvpnPortKey || jsonKey == V2rayUuidKey
                    || jsonKey == HostnameKey || jsonKey == V2rayHostKey || jsonKey == V2rayPathKey
                    || jsonKey == UsernameKey || jsonKey == PasswordKey
                    )
                {
                    // AES + XXTEA
                    return DecryptOuter(ciphertext);
                }
                return ciphertext;
            }
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS50cnB0dW5uZWwueHl6";

        public override string SampleVersion => "1.0.8";

        protected override string RepoName => Encoding.ASCII.FromBase64String("SmNhY2Fub2cxMi90cmluZXQtcHJvLXJlYm9ybi1hdXRv");

        protected override string ConfigName => Encoding.ASCII.FromBase64String("VHJpbmV0djU=");

        public override bool HasProtocol(ServerProtocol protocol)
        {
            return protocol == ServerProtocol.OpenVPN || protocol == ServerProtocol.V2Ray || protocol == ServerProtocol.SSH;
        }
    }

    public sealed class ShMemeIzph : VPNProviderGithubRepoFileBase<ShMemeIzph.Parser>
    {
        public sealed class Parser : SocksHttpRenzParser<Parser>
        {
            private static readonly byte[] s_OuterKeyDerivation =
            {
                0x89, 0x68, 0xCB, 0x6E, 0x89, 0x51, 0x05, 0xBE, 0x62, 0x58,
                0x39, 0xAD, 0x9B, 0x9B, 0xA6, 0xAC, 0xE8, 0xDC, 0xD4, 0x41,
                0x3D, 0x7C, 0x5E, 0xCF, 0xAA, 0x10, 0x69, 0x41, 0x3F, 0xFE,
                0xB0, 0x44
            };

            private static readonly byte[] s_OuterIV =
            {
                0x49, 0xE5, 0x9F, 0xDF, 0x67, 0xEB, 0x47, 0x9C, 0xE8, 0xB9,
                0x6C, 0x24, 0xD2, 0x49, 0x5B, 0xD1
            };


            private static readonly byte[] s_InnerSalt =
            {
                0xC2, 0x7F, 0xD7, 0xBE, 0xE1, 0x71, 0x96, 0xD6, 0x50, 0x53,
                0x08, 0x86, 0xCF, 0x4C, 0x24, 0xF5, 0x2C, 0xAC, 0x5A, 0xBB,
                0x8B, 0xFF, 0x6A, 0xD3, 0xA4, 0x8E, 0xBB, 0x10, 0xF4, 0xB1,
                0xF6, 0x32
            };


            protected override byte[] OuterKeyDerivation => s_OuterKeyDerivation;

            protected override byte[] OuterIV => s_OuterIV;

            protected override byte[] InnerSalt => s_InnerSalt;

            protected override byte OuterRotate => 2;
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5penBocHJvdjIubmV0";

        public override string SampleVersion => "1.0.8";

        protected override string RepoName => Encoding.ASCII.FromBase64String("a2lyYW5vYmxlL2NvbmZpZw==");

        protected override string ConfigName => Encoding.ASCII.FromBase64String("aXpwaDIwMjY=");

        public override bool HasProtocol(ServerProtocol protocol)
        {
            return protocol == ServerProtocol.OpenVPN || protocol == ServerProtocol.V2Ray || protocol == ServerProtocol.SSH;
        }
    }

    public sealed class ShMemeIh : VPNProviderGithubRepoFileBase<ShMemeIh.Parser>
    {
        public sealed class Parser : SocksHttpRenzParser<Parser>
        {
            private static readonly byte[] s_OuterKeyDerivation =
            {
                0xDE, 0xB7, 0x22, 0x21, 0xBE, 0x46, 0x52, 0xC3, 0x47, 0xF9,
                0x30, 0xE8, 0x5A, 0xDC, 0x29, 0x97, 0x0C, 0xCD, 0x49, 0x9C,
                0xF4, 0x2E, 0x36, 0x1B, 0x3D, 0x6B, 0x14, 0x91, 0x89, 0x12,
                0xBF, 0x3B
            };

            private static readonly byte[] s_OuterIV =
            {
                0x2D, 0x2F, 0x31, 0x12, 0xA2, 0x71, 0xED, 0xBB, 0xA9, 0xA4,
                0x1A, 0xD5, 0x8A, 0x3A, 0x99, 0xBF
            };


            private static readonly byte[] s_InnerSalt =
            {
                0x70, 0xED, 0x50, 0x84, 0x28, 0xFF, 0x7B, 0x5B, 0xCD, 0xE0,
                0xBC, 0xDD, 0x3B, 0x94, 0x74, 0x93, 0x2A, 0xB1, 0xCA, 0xBC,
                0x5F, 0xF6, 0x87, 0x0E, 0x6E, 0x58, 0x4B, 0x4F, 0xA7, 0x92,
                0x5F, 0x55
            };


            protected override byte[] OuterKeyDerivation => s_OuterKeyDerivation;

            protected override byte[] OuterIV => s_OuterIV;

            protected override byte[] InnerSalt => s_InnerSalt;

            protected override byte OuterRotate => 2;
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPW9yZy5paG9tZXZwbi54eXo=";

        public override string SampleVersion => "2.6";

        protected override string RepoName => Encoding.ASCII.FromBase64String("TUFLRS1NT05FWS1NSUxMSU9OLURPTExBUi1QRVItREFZLzduZXQtMTZrYlYy");

        protected override string ConfigName => Encoding.ASCII.FromBase64String("N05FVC1Db3JlLmpz");

        public override bool HasProtocol(ServerProtocol protocol)
        {
            return protocol == ServerProtocol.OpenVPN || protocol == ServerProtocol.V2Ray || protocol == ServerProtocol.SSH;
        }
    }

    public sealed class ShMemeHamo : VPNProviderGithubRepoFileBase<ShMemeIh.Parser> // not a typo, same keys are used!
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPW9yZy5oYW1vdHVubmVscGx1cy54eXo=";

        public override string SampleVersion => "1.5";

        protected override string RepoName => Encoding.ASCII.FromBase64String("TUFLRS1NT05FWS1NSUxMSU9OLURPTExBUi1QRVItREFZL0VOWi1UVU5ORUwtTGl0ZQ==");

        protected override string ConfigName => Encoding.ASCII.FromBase64String("RU5aX1R1bm5lbC5qcw==");

        public override bool HasProtocol(ServerProtocol protocol)
        {
            return protocol == ServerProtocol.OpenVPN || protocol == ServerProtocol.V2Ray || protocol == ServerProtocol.SSH;
        }
    }

    public sealed class ShMemeMc : ProviderBase<ShMemeMc.Parser>
    {
        public sealed class Parser : SocksHttpRenzParser2<Parser>
        {
            private static readonly byte[] s_OuterKeyDerivation =
            {
                0xA2, 0xC3, 0x08, 0xAD, 0x27, 0x3B, 0x6B, 0x54, 0x6C, 0x73,
                0x80, 0x8F, 0xF9, 0x59, 0xEA, 0x62, 0x9E, 0x6C, 0x43, 0x1C,
                0x01, 0x1F, 0xFB, 0xE9, 0x00, 0x5B, 0x4D, 0x05, 0xD5, 0xCC,
                0xCE, 0x63
            };

            private static readonly byte[] s_OuterIV =
            {
                0x61, 0x2B, 0x08, 0x1B, 0x49, 0xB6, 0xA4, 0xBC, 0x40, 0xC7,
                0x36, 0x71, 0x34, 0xA8, 0x26, 0x5B
            };


            private static readonly byte[] s_InnerSalt =
            {
                0x4B, 0xDA, 0x80, 0xEF, 0x5C, 0xBE, 0x84, 0xA5, 0x72, 0xC8,
                0x16, 0x5C, 0xCD, 0xD1, 0x2E, 0x0F, 0xAC, 0xEB, 0xB0, 0x14,
                0x22, 0x92, 0xD5, 0x94, 0xC4, 0x4D, 0x7A, 0x71, 0x80, 0xEE,
                0x00, 0xCB
            };


            protected override byte[] OuterKeyDerivation => s_OuterKeyDerivation;

            protected override byte[] OuterIV => s_OuterIV;

            protected override byte[] InnerSalt => s_InnerSalt;
            protected override byte OuterRotate => 2;

            protected override string OvpnConfTemplate => Encoding.ASCII.FromBase64String(
                "Y2xpZW50DQpkZXYgdHVuDQpwcm90byB0Y3ANCnJlbW90ZSBTRVJWRVJJUEFERFJFU1NIRVJFIDEx"+
                "OTQNCmNpcGhlciBub25lDQphdXRoIG5vbmUNCmF1dGgtdXNlci1wYXNzDQojcGluZy10aW1lci1y"+
                "ZW0NCnJlZGlyZWN0LWdhdGV3YXkgZGVmMQ0Kc2V0ZW52IENMSUVOVF9DRVJUIDANCnZlcmIgMw0K"+
                "PGNhPg0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlDTVRDQ0FacWdBd0lCQWdJVUFh"+
                "UUJBcE1TMmRZQnFZUGNBM1BhN2Nqanc3Y3dEUVlKS29aSWh2Y05BUUVMDQpCUUF3RHpFTk1Bc0dB"+
                "MVVFQXd3RVMyOWlXakFlRncweU1EQTNNakl5TWpJek16TmFGdzB6TURBM01qQXlNakl6DQpNek5h"+
                "TUE4eERUQUxCZ05WQkFNTUJFdHZZbG93Z1o4d0RRWUpLb1pJaHZjTkFRRUJCUUFEZ1kwQU1JR0pB"+
                "b0dCDQpBTUY0NlVWaTJPNXBacGRkT1B5elUyRXlJcnI4TnJwWHFzOEJsWWhVanhPY0Nya01qRnUy"+
                "RzloazdRSVo0cU8wDQpHV1ZacFBoWWs1cVdrK0x4Q3NyeXJTb2UwYTVIYXFJeWU4QkZKbVhWMGsr"+
                "Ty8zZTZrMDZVR05paTNneEJXUXBGDQo3ci8yQ3lRTHVzOU9TcFFQWXN6QnlCdnRrd2lCQW8vVjk4"+
                "amRwbStFVnU2dEFnTUJBQUdqZ1lrd2dZWXdIUVlEDQpWUjBPQkJZRUZHUkpNbS8rWm1MeFYwMjdr"+
                "YWhkdlNZK1VhVFNNRW9HQTFVZEl3UkRNRUdBRkdSSk1tLytabUx4DQpWMDI3a2FoZHZTWStVYVRT"+
                "b1JPa0VUQVBNUTB3Q3dZRFZRUUREQVJMYjJKYWdoUUJwQUVDa3hMWjFnR3BnOXdEDQpjOXJ0eU9Q"+
                "RHR6QU1CZ05WSFJNRUJUQURBUUgvTUFzR0ExVWREd1FFQXdJQkJqQU5CZ2txaGtpRzl3MEJBUXNG"+
                "DQpBQU9CZ1FDMGY4d2I1aHlFT0VFWDY0bDhRQ05weWQvV0xqb2VFNWJFK3huSWNLRStYcEVvRFJa"+
                "d3VnTG95UWRjDQpIS2EzYVJITnFLcFI3SDY5NlhKUmVvNCtwb2NEZXlqN3JBVGJPNWRabVNNTm1N"+
                "emJzalFlWHV4MFhqd21aSUh1DQplREtNZWZEaTBaZmlabW5VMm5qbVRuY3laS3h2MThJa2p3czBN"+
                "eWM4UHRBeHkycWRjQT09DQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tDQo8L2NhPg=="
            );
        }
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPW9yZy5tY25ldHZwbi5hcHA=";

        public override string SampleVersion => "1.1";

        protected override string RequestUri => Encoding.ASCII.FromBase64String("aHR0cHM6Ly9hdG5ldHZwbi54eXovYXBpL2FwcD9qc29uPTc1OWI5Njc4NzVjYjdlZTZmNTcz");
    }
}
