using LibFreeVPN.Memecrypto;
using LibFreeVPN.ProviderHelpers;
using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

// Android apps. SocksHttp using SSH + V2ray.
namespace LibFreeVPN.Providers.ShMpn
{
    public abstract class ParserBase<TType> : SocksHttpParser<TType>
        where TType : ParserBase<TType>, new()
    {
        protected override IEnumerable<string> OptionalServersArrayKeys => "Networks".EnumerableSingle();
        protected override string CountryNameKey => "FLAG";
        protected override string ServerTypeKey => "isV2ray";
        protected override string V2RayKey => "v2rayJson";
        protected override string UsernameKey => "XUser";
        protected override string PasswordKey => "XPass";

        protected virtual string SSHPrivkeyKey => "servermessage";

        protected abstract string OuterKeyId { get; }
        protected abstract uint[] InnerKey { get; }

        protected virtual HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA256;
        protected virtual int PbkdfRounds => 5000;

        protected override string DecryptOuter(string ciphertext)
        {
            var bytes = Convert.FromBase64String(ciphertext);
            var seed = new byte[0x10];
            var iv = new byte[0x10];
            var cipherTextBytes = new byte[bytes.Length - 0x20];
            Buffer.BlockCopy(bytes, 0, seed, 0, 0x10);
            Buffer.BlockCopy(bytes, 0x10, iv, 0, 0x10);
            Buffer.BlockCopy(bytes, 0x20, cipherTextBytes, 0, cipherTextBytes.Length);

            using (var aes = new AesManaged())
            {
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Padding = PaddingMode.PKCS7;
                byte[] key = null;
                using (var pbkdf2 = new Pbkdf2(OuterKeyId, seed, PbkdfRounds, HashAlgorithm))
                    key = pbkdf2.GetBytes(0x20);
                using (var dec = aes.CreateDecryptor(key, iv))
                {
                    return Encoding.UTF8.GetString(dec.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length));
                }
            }
        }

        private static void XteaDecryptBlock(uint num_rounds, uint[] v, uint[] key)
        {
            uint i;
            uint v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * num_rounds;
            for (i = 0; i < num_rounds; i++)
            {
                v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
                sum -= delta;
                v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            }
            v[0] = v0; v[1] = v1;
        }

        private static bool s_IsBigEndian = BitConverter.GetBytes(0x12345678)[0] == 0x12;

        private static uint SwapEndianness(uint x)
        {
            // swap adjacent 16-bit blocks
            x = (x >> 16) | (x << 16);
            // swap adjacent 8-bit blocks
            return ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8);
        }

        private static void SwapEndianness(ref uint x) => x = SwapEndianness(x);

        private string DecryptInner(string ciphertext)
        {
            if (ciphertext.Length == 0) return ciphertext;
            var blocks = ciphertext.Split(' ');
            var plaintext = new byte[blocks.Length * 8];

            int offset = 0;

            foreach (var block in blocks)
            {
                var bytes = Convert.FromBase64String(block);
                uint[] ints = new uint[2] {
                    BitConverter.ToUInt32(bytes, 0),
                    BitConverter.ToUInt32(bytes, 4)
                };
                if (!s_IsBigEndian)
                {
                    SwapEndianness(ref ints[0]);
                    SwapEndianness(ref ints[1]);
                }
                XteaDecryptBlock(32, ints, InnerKey);
                if (!s_IsBigEndian)
                {
                    SwapEndianness(ref ints[0]);
                    SwapEndianness(ref ints[1]);
                }
                Buffer.BlockCopy(ints, 0, plaintext, offset, 4);
                Buffer.BlockCopy(ints, 4, plaintext, offset + 4, 4);
                offset += 8;
            }

            return Encoding.UTF8.GetString(plaintext).TrimEnd('\x00');
        }

        protected override string DecryptInner(string jsonKey, string ciphertext)
        {
            if (jsonKey != HostnameKey && jsonKey != UsernameKey && jsonKey != PasswordKey && jsonKey != SSHPrivkeyKey && jsonKey != V2RayKey) return ciphertext;

            return DecryptInner(ciphertext);
        }

        protected override IEnumerable<IVPNServer> ParseServer(JsonDocument root, JsonElement server, IReadOnlyDictionary<string, string> passedExtraRegistry)
        {
            string serverType = null;
            if (!server.TryGetProperty(ServerTypeKey, out var serverTypeJson))
            {
                // This is Network element, aka SSH tunnel
                serverType = "ssh";
            }
            else
            {
                switch (serverTypeJson.ValueKind)
                {
                    case JsonValueKind.String:
                        serverType = serverTypeJson.GetString().ToLower() == "true" ? "v2ray" : "unknown";
                        break;
                    case JsonValueKind.True:
                        serverType = "v2ray";
                        break;
                    case JsonValueKind.False:
                        serverType = "unknown";
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }

            string hostname, port;
            string username = null, password = null, v2ray = null;
            string name, country;

            if (!server.TryGetPropertyString(ServerNameKey, out name)) throw new InvalidDataException();

            var extraRegistry = new Dictionary<string, string>();
            foreach (var kv in passedExtraRegistry) extraRegistry.Add(kv.Key, kv.Value);
            extraRegistry.Add(ServerRegistryKeys.DisplayName, name);
            if (server.TryGetPropertyString(CountryNameKey, out country))  extraRegistry.Add(ServerRegistryKeys.Country, country);

            switch (serverType.ToLower())
            {
                case "ssh": // ssh
                    if (!server.TryGetPropertyString(HostnameKey, out hostname)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(PortKey, out port)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                    server.TryGetPropertyString(PasswordKey, out password);
                    if (string.IsNullOrEmpty(password) && !server.TryGetPropertyString(SSHPrivkeyKey, out password)) throw new InvalidDataException();
                    return hostname.Split(';').Select((host) => new SSHServer(host, port, username, password, extraRegistry)).ToList();
                case "v2ray": // v2ray
                    if (!server.TryGetPropertyString(V2RayKey, out v2ray)) throw new InvalidDataException();
                    return V2RayServer.ParseConfigFull(v2ray, extraRegistry);
                default:
                    throw new InvalidDataException();
            }
        }
    }

    public abstract class ParserBaseRot<TType> : ParserBase<TType>
        where TType : ParserBaseRot<TType>, new()
    {
        protected override string ServersArrayKey => "serversList";
        protected override IEnumerable<string> OptionalServersArrayKeys => "networksList".EnumerableSingle();
        protected override string ServerNameKey => "name";
        protected override string CountryNameKey => "flag";
        protected override string V2RayKey => "v2rayEntry";
        protected override string HostnameKey => "host";
        protected override string PortKey => "portDirect";
        protected override string UsernameKey => "username";
        protected override string PasswordKey => "password";

        protected override string SSHPrivkeyKey => "pubkey";


        internal static ThreadLocal<string> s_CurrentOuterKey = new ThreadLocal<string>();
        protected override HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA1;
        protected override int PbkdfRounds => 10000;

        protected override string OuterKeyId => s_CurrentOuterKey.Value;
        protected override uint[] InnerKey => new uint[4];

        private static string ReverseRot1(string text, int offset, int length)
        {
            var chars = text.ToCharArray();
            for (int i = 0; i < length; i++)
            {
                var idx = i + offset;
                var chr = chars[idx];
                if (chr < 'A' || chr == 0x60 || chr > 'z') continue;
                int baseVal = 'A' + (chr & 0x20);
                chars[idx] = (char)(((chr - baseVal + 25) % 26) + baseVal);
            }
            return new string(chars);
        }

        protected override string DecryptInner(string jsonKey, string ciphertext)
        {
            if (jsonKey == SSHPrivkeyKey)
            {
                var start = ciphertext.IndexOf("KEY-----");
                if (start == -1) return ciphertext;
                start += "KEY-----".Length;
                var end = ciphertext.IndexOf("-----", start);
                if (end == -1) return ciphertext;
                return ReverseRot1(ciphertext, start, end - start);
            } else if (jsonKey == V2RayKey)
            {
                if (ciphertext.StartsWith("vmess://"))
                {
                    var vmjsonText = Encoding.UTF8.GetString(Convert.FromBase64String(ciphertext.Substring("vmess://".Length)));
                    var vmjson = JsonDocument.Parse(vmjsonText);
                    if (!vmjson.RootElement.TryGetPropertyString("id", out var vmessid)) return ciphertext;
                    vmjsonText = vmjsonText.Replace(vmessid, ReverseRot1(vmessid, 0, vmessid.Length));
                    return string.Format("vmess://{0}", Convert.ToBase64String(Encoding.UTF8.GetBytes(vmjsonText)));
                }
                if (ciphertext.StartsWith("vless://") || ciphertext.StartsWith("trojan://"))
                {
                    var parsed = new UriBuilder(new Uri(ciphertext.Trim()));
                    parsed.UserName = ReverseRot1(parsed.UserName, 0, parsed.UserName.Length);
                    return parsed.ToString();
                }
            }
            return ciphertext;
        }

        protected override string DecryptOuter(string ciphertext)
        {
            ciphertext = ciphertext.Substring(0, 5) + ciphertext.Substring(8, 15) + ciphertext.Substring(26);
            var chars = Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.UTF8.GetString(Convert.FromBase64String(ciphertext)))).ToCharArray();
            Array.Reverse(chars);
            for (int i = 0; i < chars.Length; i++)
            {
                var chr = chars[i];
                if (chr < 'A' || chr == 0x60 || chr > 'z') continue;
                int baseVal = 'A' + (chr & 0x20);
                chars[i] = (char)(((chr - baseVal + 20) % 26) + baseVal);
            }

            return base.DecryptOuter(new string(chars));
        }

        public string DecryptString(string ciphertext) => DecryptOuter(ciphertext); 
    }

    public sealed class ParserConfigRot : ParserBaseRot<ParserConfigRot>
    {
        protected override string OuterKeyId => m_OuterKeyId;

        public string OverrideOuterKeyId { set => m_OuterKeyId = value; }

        private string m_OuterKeyId = "m";
    }

    public sealed class ParserRot : ParserBaseRot<ParserRot> { }

    public abstract class ShMpnBase<TParser> : VPNProviderGithubRepoFileBase<TParser>
        where TParser : ParserBase<TParser>, new()
    {
        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("TWluYURpTmFiaWwvdXBkYXRlLmxpbms="));

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH || protocol == ServerProtocol.V2Ray;
    }

    public abstract class ShMpnRotBase<TParser> : ShMpnBase<TParser>
        where TParser : ParserBaseRot<TParser>, new()
    {
        protected virtual string SecondConfigUrlKey => "ServerLink";
        protected virtual string InnerSeedKey => "ServerPassWD";

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl(string config)
        {
            // Decrypt the obtained config.
            var firstParser = new ParserConfigRot();
            config = firstParser.DecryptString(config);

            // Parse it to get the real key-id and the actual config url.
            var json = JsonDocument.Parse(config);
            if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (!json.RootElement.TryGetPropertyString(SecondConfigUrlKey, out var secondConfigUrl)) throw new InvalidDataException();
            if (!json.RootElement.TryGetPropertyString(InnerSeedKey, out var innerSeedKey)) throw new InvalidDataException();

            innerSeedKey = firstParser.DecryptString(innerSeedKey);

            firstParser.OverrideOuterKeyId = innerSeedKey;
            secondConfigUrl = firstParser.DecryptString(secondConfigUrl);

            // If this isn't supposed to make risky requests, ensure the domain matches.
            if (!RiskyRequests)
            {
                var parsedUrl = new Uri(secondConfigUrl);
                var firstUrl = new Uri(RequestUri);
                if (firstUrl.Host != parsedUrl.Host) throw new InvalidDataException();
            }

            // Get the second config.
            config = await ServerUtilities.HttpClient.GetStringAsync(secondConfigUrl);

            // Ensure the parser is set to use the correct key-id for this thread.
            ParserBaseRot<TParser>.s_CurrentOuterKey.Value = innerSeedKey;

            // Try to parse the config.
            return await GetServersAsyncImpl<TParser>(config);
        }
    }



    public sealed class ShMpnBee : ShMpnBase<ShMpnBee.Parser>
    {
        public sealed class Parser : ParserBase<Parser>
        {
            protected override string OuterKeyId => Encoding.ASCII.GetString(Convert.FromBase64String("MTk4Nj9AUkNBMTk4Nj9AUkNB"));

            protected override uint[] InnerKey => new uint[] { 0xA56BABCD, 0, 0, 0 };
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWRldi5kZXY3LmJlZQ==";

        public override string SampleVersion => "38.4";

        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("YWJkb2VsMTAzL3pvbmV0dW5uZWw="));

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("YmlnanNvbg=="));
    }

    public sealed class ShMpnMp : ShMpnRotBase<ParserRot>
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPXZwbi5taW5hcHJvbmV0LmNvbS5lZw==";

        public override string SampleVersion => "58.0";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("bWluYXByb25ldF91cGRhdGVy"));
    }
    public sealed class ShMpnOc : ShMpnRotBase<ParserRot>
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPW9wZW5jdXN0b20ubWluYXByb25ldC5jb20uZWc=";

        public override string SampleVersion => "7.0";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("b3BlbmN1c3RvbV91cGRhdGVy"));
    }
    public sealed class ShMpnSd : ShMpnRotBase<ParserRot>
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPXNsb3dkbnMubWluYXByb25ldHZwbi5jb20uZWc=";

        public override string SampleVersion => "2.0";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("c2xvd2Ruc191cGRhdGVy"));
    }
}
