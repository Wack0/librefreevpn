using HkdfStandard;
using LibFreeVPN.Memecrypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Web;

namespace LibFreeVPN.Servers
{
    // Parser for SocksHtttp configs. (android client)
    // There are dozens of forks of this, each with their own obfuscation methods and memecrypto applied to configs etc
    // Therefore, implement some hierarchy to deal with it, implement the most common method and so on.
    public abstract class SocksHttpParser<TType> : VPNJsonArrInObjMultiProviderParser<TType>
        where TType : SocksHttpParser<TType>, new()
    {

        // Server object
        protected virtual string ServerNameKey => "Name";
        protected virtual string CountryNameKey => "Flag";
        protected virtual string HostnameKey => "ServerIP";
        protected virtual string PortKey => "ServerPort";

        protected virtual string UsernameKey => "ServerUser";
        protected virtual string PasswordKey => "ServerPass";

        protected virtual string V2RayKey => "V2RayJson";

        protected virtual string ServerTypeKey => "Tunnel";

        protected override IEnumerable<IVPNServer> ParseServer(JsonDocument root, JsonElement server, IReadOnlyDictionary<string, string> passedExtraRegistry)
        {
            if (!server.TryGetPropertyString(ServerTypeKey, out var serverType))
            {
                // some variants do not have ServerType and just support SSH
                serverType = "ssh";
            }
            string hostname, port;
            string username = null, password = null, v2ray = null;
            string name, country;

            if (!server.TryGetPropertyString(ServerNameKey, out name)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(CountryNameKey, out country)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(HostnameKey, out hostname)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(PortKey, out port)) throw new InvalidDataException();

            var extraRegistry = new Dictionary<string, string>();
            foreach (var kv in passedExtraRegistry) extraRegistry.Add(kv.Key, kv.Value);
            extraRegistry.Add(ServerRegistryKeys.DisplayName, name);
            extraRegistry.Add(ServerRegistryKeys.Country, country);

            if (serverType.ToLower().StartsWith("ssh ")) serverType = "ssh";

            switch (serverType.ToLower())
            {
                case "ssh":
                    if (!server.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(PasswordKey, out password)) throw new InvalidDataException();
                    return new SSHServer(hostname, port, username, password, extraRegistry).EnumerableSingle<IVPNServer>();
                case "v2ray":
                    if (!server.TryGetPropertyString(V2RayKey, out v2ray)) throw new InvalidDataException();
                    return V2RayServer.ParseConfigFull(v2ray, extraRegistry);
                default:
                    throw new InvalidDataException();
            }
        }
    }

    // Parser for SocksHttp configs (with OpenVPN+SSH support - same server running both)
    public abstract class SocksHttpWithOvpnParser<TType> : SocksHttpParser<TType>
        where TType : SocksHttpWithOvpnParser<TType>, new()
    {
        protected virtual string OvpnKey => "OvpnCertificate";
        protected virtual string OvpnPortKey => "TCPPort";
        protected override string PortKey => "SSHPort";
        protected override string UsernameKey => "Username";
        protected override string PasswordKey => "Password";
        protected override string V2RayKey => "V2Ray";
        protected override string ServerTypeKey => "SelectType";
        protected override IEnumerable<IVPNServer> ParseServer(JsonDocument root, JsonElement server, IReadOnlyDictionary<string, string> passedExtraRegistry)
        {
            if (!server.TryGetPropertyString(ServerTypeKey, out var serverType)) throw new InvalidDataException();

            string hostname, port;
            string username = null, password = null, v2ray = null, ovpnconf = null, ovpnport = null;
            string name, country;

            if (!server.TryGetPropertyString(ServerNameKey, out name)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(CountryNameKey, out country)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(HostnameKey, out hostname)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(PortKey, out port)) throw new InvalidDataException();

            var extraRegistry = new Dictionary<string, string>();
            foreach (var kv in passedExtraRegistry) extraRegistry.Add(kv.Key, kv.Value);
            extraRegistry.Add(ServerRegistryKeys.DisplayName, name);
            extraRegistry.Add(ServerRegistryKeys.Country, country);

            switch (serverType.ToLower())
            {
                case "default":
                case "ssh":
                    if (!server.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(PasswordKey, out password)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(OvpnKey, out ovpnconf) || string.IsNullOrEmpty(ovpnconf))
                    {
                        if (root.RootElement.TryGetPropertyString(OvpnKey, out ovpnconf)) ovpnconf = DecryptInner(OvpnKey, ovpnconf);
                        else ovpnconf = null;
                    }
                    if (!server.TryGetPropertyString(OvpnPortKey, out ovpnport)) ovpnport = null;

                    var sshOnlyEnum = new SSHServer(hostname, port, username, password, extraRegistry).EnumerableSingle<IVPNServer>();
                    if (!string.IsNullOrEmpty(ovpnconf))
                    {
                        var ovpnRegistry = new Dictionary<string, string>();
                        foreach (var kv in extraRegistry) ovpnRegistry.Add(kv.Key, kv.Value);
                        ovpnRegistry.Add(ServerRegistryKeys.Username, username);
                        ovpnRegistry.Add(ServerRegistryKeys.Password, password);
                        return OpenVpnServer.ParseConfigFull(OpenVpnServer.InjectHostIntoConfig(ovpnconf, hostname, ovpnport), ovpnRegistry).Concat(sshOnlyEnum);
                    }
                    return sshOnlyEnum;
                case "v2ray":
                    if (!server.TryGetPropertyString(V2RayKey, out v2ray)) throw new InvalidDataException();
                    return V2RayServer.ParseConfigFull(v2ray, extraRegistry);
                default:
                    throw new InvalidDataException();
            }
        }
    }

    public abstract class SocksHttpWithOvpnNumericParser<TType> : SocksHttpWithOvpnParser<TType>
        where TType : SocksHttpWithOvpnNumericParser<TType>, new()
    {
        protected override string CountryNameKey => "FLAG";
        protected override string ServerTypeKey => "serverType";
        protected override string OvpnPortKey => "TcpPort";
        protected override string OvpnKey => "ovpnCertificate";

        protected virtual bool OvpnPortIsBogus => false;

        protected virtual string ProtocolTypeOvpn => "0";
        protected virtual string ProtocolTypeSsh => "1";
        protected virtual string ProtocolTypeV2ray => "3";

        protected override IEnumerable<IVPNServer> ParseServer(JsonDocument root, JsonElement server, IReadOnlyDictionary<string, string> passedExtraRegistry)
        {
            string serverType = null;
            if (!server.TryGetProperty(ServerTypeKey, out var serverTypeJson)) throw new InvalidDataException();
            switch (serverTypeJson.ValueKind)
            {
                case JsonValueKind.String:
                    serverType = serverTypeJson.GetString();
                    break;
                case JsonValueKind.Number:
                    serverType = serverTypeJson.GetInt32().ToString();
                    break;
                default:
                    throw new InvalidDataException();
            }

            string  port;
            string username = null, password = null, v2ray = null, ovpnconf = null;
            string name, country;

            if (!server.TryGetPropertyString(ServerNameKey, out name)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(CountryNameKey, out country)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(HostnameKey, out var hostnames)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(OvpnPortKey, out port)) throw new InvalidDataException();

            // if hostname contains semicolon then it's a list of hostnames
            return hostnames.Split(';').SelectMany((hostname) =>
            {
                var extraRegistry = new Dictionary<string, string>();
                foreach (var kv in passedExtraRegistry) extraRegistry.Add(kv.Key, kv.Value);
                extraRegistry.Add(ServerRegistryKeys.DisplayName, name);
                extraRegistry.Add(ServerRegistryKeys.Country, country);

                var protocolType = serverType.ToLower();
                if (protocolType == ProtocolTypeOvpn)
                {
                    if (!server.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(PasswordKey, out password)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(OvpnKey, out ovpnconf) || string.IsNullOrEmpty(ovpnconf))
                    {
                        if (root.RootElement.TryGetPropertyString(OvpnKey, out ovpnconf)) ovpnconf = DecryptInner(OvpnKey, ovpnconf);
                        else ovpnconf = null;
                    }
                    if (string.IsNullOrEmpty(ovpnconf)) throw new InvalidDataException();
                    if (OvpnPortIsBogus)
                    {
                        // Port in the JSON object is bogus, the real port is in the openvpn config
                        var real = OpenVpnServer.ParseConfigFull(ovpnconf).FirstOrDefault();
                        if (real == null || !real.Registry.TryGetValue(ServerRegistryKeys.Port, out port)) throw new InvalidDataException();

                    }
                    var ovpnRegistry = new Dictionary<string, string>();
                    foreach (var kv in extraRegistry) ovpnRegistry.Add(kv.Key, kv.Value);
                    ovpnRegistry.Add(ServerRegistryKeys.Username, username);
                    ovpnRegistry.Add(ServerRegistryKeys.Password, password);
                    return OpenVpnServer.ParseConfigFull(OpenVpnServer.InjectHostIntoConfig(ovpnconf, hostname, port), ovpnRegistry);
                } else if (protocolType == ProtocolTypeSsh)
                {
                    if (!server.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(PasswordKey, out password)) throw new InvalidDataException();
                    return new SSHServer(hostname, port, username, password, extraRegistry).EnumerableSingle<IVPNServer>();
                } else if (protocolType == ProtocolTypeV2ray)
                {
                    if (!server.TryGetPropertyString(V2RayKey, out v2ray)) throw new InvalidDataException();
                    return V2RayServer.ParseConfigFull(v2ray, extraRegistry);
                } else
                {
                    throw new InvalidDataException();
                }
            }).ToArray();
        }
    }

    public abstract class SocksHttpRenzParser<TType> : SocksHttpWithOvpnNumericParser<TType>
        where TType : SocksHttpRenzParser<TType>, new()
    {
        private sealed class RenzV2rayLinkParser
        {
            public string id, add, port, path, host, sni, tls;
            public string Type0Convert()
            {
                var jsonConfig = new JsonObject()
                {
                    ["v"] = "2",
                    ["add"] = add,
                    ["aid"] = "0",
                    ["alpn"] = "",
                    ["fp"] = "",
                    ["host"] = host,
                    ["id"] = id,
                    ["net"] = "ws",
                    ["path"] = path,
                    ["port"] = port,
                    ["ps"] = "Vmess",
                    ["scy"] = "auto",
                    ["sni"] =  sni,
                    ["tls"] = tls,
                    ["type"] = "",
                };
                return string.Format("vmess://{0}", Convert.ToBase64String(Encoding.UTF8.GetBytes(jsonConfig.ToJsonString())));
            }

            public string Type1Convert()
            {
                var jsonConfig = new JsonObject()
                {
                    ["v"] = "2",
                    ["add"] = add,
                    ["aid"] = "0",
                    ["alpn"] = "",
                    ["fp"] = "",
                    ["host"] = "",
                    ["id"] = id,
                    ["net"] = "grpc",
                    ["path"] = path,
                    ["port"] = port,
                    ["ps"] = "Renz-V2Ray",
                    ["scy"] = "none",
                    ["sni"] = sni,
                    ["tls"] = tls,
                    ["type"] = "gun",
                };
                return string.Format("vmess://{0}", Convert.ToBase64String(Encoding.UTF8.GetBytes(jsonConfig.ToJsonString())));
            }

            public string Type2Convert()
            {
                var jsonConfig = new JsonObject()
                {
                    ["v"] = "2",
                    ["add"] = add,
                    ["aid"] = "0",
                    ["alpn"] = "",
                    ["fp"] = "",
                    ["host"] = "",
                    ["id"] = id,
                    ["net"] = "grpc",
                    ["path"] = path,
                    ["port"] = port,
                    ["ps"] = "Renz-V2Ray",
                    ["scy"] = "none",
                    ["sni"] = sni,
                    ["tls"] = tls,
                    ["type"] = "gun",
                };
                return string.Format("vmess://{0}", Convert.ToBase64String(Encoding.UTF8.GetBytes(jsonConfig.ToJsonString())));
            }

            public string Type3Convert()
            {
                return string.Format("vless://{0}@{1}:{2}?path={3}&security={4}&encryption=none&host={5}&type=ws&sni={6}#Renz-V2Ray",
                    id, add, port, HttpUtility.UrlEncode(path), tls, host, sni);
            }

            public string Type4Convert()
            {
                return string.Format("vless://{0}@{1}:{2}?mode=gun&security={3}&encryption=none&type=grpc&serviceName={4}&sni={5}#Renz-V2Ray",
                    id, add, port, tls, HttpUtility.UrlEncode(path), sni);
            }

            public string Type5Convert()
            {
                return string.Format("vless://{0}@{1}:{2}?path={3}&encryption=none&type=ws#Renz-V2Ray",
                    id, add, port, HttpUtility.UrlEncode(path));
            }

            public string ConvertGeneric(string type)
            {
                if (type == "0") return Type0Convert();
                if (type == "1") return Type1Convert();
                if (type == "2") return Type2Convert();
                if (type == "3") return Type3Convert();
                if (type == "4") return Type4Convert();
                if (type == "5") return Type5Convert();
                throw new ArgumentOutOfRangeException(nameof(type));
            }
        }

        protected virtual string OvpnConfTemplate => string.Empty;
        protected virtual bool AdditionalTweak => true;

        protected override string CountryNameKey => "flag";
        protected override string HostnameKey => "ServerIPHost";
        protected override string ServerTypeKey => "Protocol";
        protected override string OvpnPortKey => "OpenVPNTCPPort";
        protected override string OvpnKey => "CustomCert";


        protected virtual string V2rayTypeKey => "V2RayType";
        protected virtual string V2rayHostKey => "V2RayHost";
        protected virtual string V2rayUuidKey => "UUID";
        protected virtual string V2rayPathKey => "PATH";


        protected virtual uint TeaDelta => 0x7A56D3E1;

        protected virtual byte OuterRotate => 0;

        protected XXTEA XXTEA => XXTEA.Create(TeaDelta);

        protected abstract byte[] OuterKeyDerivation { get; }

        protected virtual byte[] OuterKey
        {
            get
            {
                using (var sha = new SHA256Managed())
                {
                    return sha.ComputeHash(OuterKeyDerivation);
                }
            }
        }

        protected abstract byte[] OuterIV { get; }

        protected virtual byte[] InnerKey { get => OuterKeyDerivation; }
        protected abstract byte[] InnerSalt { get; }

        private byte[] m_InnerSalt16;
        private bool m_InnerSalt16Initialised = false;

        protected virtual byte[] InnerSalt16
        {
            get
            {
                if (!m_InnerSalt16Initialised)
                {
                    m_InnerSalt16 = new byte[0x10];
                    Buffer.BlockCopy(InnerSalt, 0, m_InnerSalt16, 0, 0x10);
                }
                return m_InnerSalt16;
            }
        }
        protected virtual byte[] InnerSalt32 { get => InnerSalt; }


        protected virtual byte[] InnerKeyFish { get => HkdfDeriveKey(InnerKey, InnerSalt32, 32); } // HKDF-SHA256, other hardcoded salt, hardcoded key (32 bytes derived)
        protected virtual byte[] InnerKeyAES { get => HkdfDeriveKey(InnerKey, InnerSalt16, 16); } // HKDF-SHA256, hardcoded salt, hardcoded key (16 bytes derived)
        protected virtual byte[] InnerIV { get => OuterIV; }

        protected virtual byte[] InnerKey2 { get => Pbkdf2DeriveKey(InnerKey, InnerSalt32, 32); } // PBKDF2-SHA256, other hardcoded salt, hardcoded key (32 bytes derived)

        private static byte[] s_UnusedIV = new byte[0x20];

        private static byte[] Pbkdf2DeriveKey(byte[] key, byte[] salt, int length)
        {
            return (key, salt, length, true).SingleInstance((data) =>
            {
                using (var pbkdf2 = new Pbkdf2(data.key, data.salt, 100000, HashAlgorithmName.SHA256))
                    return pbkdf2.GetBytes(data.length);
            });
        }

        private static byte[] HkdfDeriveKey(byte[] key, byte[] salt, int length)
        {
            return (key, salt, length, false).SingleInstance((data) => Hkdf.DeriveKey(HashAlgorithmName.SHA256, data.key, data.length, data.salt));
        }

        private static byte[] DecodeSubstitution(string str)
        {
            int b = 0;
            int bit = 0;

            var ret = new List<byte>();
            for (int i = 0; i < str.Length; i++)
            {
                var last = str[i];
                if (last != '\u200b' && last != '\u200c') continue;
                b <<= 1;
                b |= last == '\u200c' ? 1 : 0;
                bit++;
                if (bit == 8)
                {
                    int next = (((b << 1) & 0xAAAA) | ((b >> 1) & 0x5555)) ^ 0x5A;
                    ret.Add((byte)next);
                    b = 0;
                    bit = 0;
                }
            }
            return ret.ToArray();
        }

        private static bool IsSubstitution(string str)
        {
            if (str.Length == 0) return false;
            for (int i = 0; i < str.Length; i++)
            {
                var last = str[i];
                if (last < '\u200b' || last > '\u200d') return false;
            }
            return true;
        }

        protected static byte[] DecryptAes(byte[] cipherTextBytes, byte[] key, byte[] iv)
        {
            using (var aes = new AesManaged())
            {
                aes.BlockSize = 128;
                aes.KeySize = 128;
                aes.Padding = PaddingMode.PKCS7;
                var key128 = new byte[0x10];
                Buffer.BlockCopy(key, 0, key128, 0, 0x10);
                using (var dec = aes.CreateDecryptor(key128, iv))
                {
                    return dec.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length);
                }
            }
        }

        private static string DecryptAes(byte[] cipherTextBytes, byte[] key)
        {
            using (var aes = new AesManaged())
            {
                var iv = new byte[0x10];
                Buffer.BlockCopy(cipherTextBytes, 0, iv, 0, 0x10);
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Padding = PaddingMode.PKCS7;
                using (var dec = aes.CreateDecryptor(key, iv))
                {
                    return Encoding.UTF8.GetString(dec.TransformFinalBlock(cipherTextBytes, 0x10, cipherTextBytes.Length - 0x10));
                }
            }
        }

        protected static byte[] DecryptAes(string ciphertext, byte[] key, byte[] iv)
        {
            return DecryptAes(Convert.FromBase64String(ciphertext), key, iv);
        }

        private static byte[] DecryptFish(byte[] cipherTextBytes, byte[] key, bool extratweak)
        {
            var tweak = new ulong[2] { 0, 0 };
            var plainTextBytes = new byte[cipherTextBytes.Length];
            for (int offset = 0; offset < cipherTextBytes.Length; offset += 0x20)
            {
                using (var fish = new Threefish())
                {
                    fish.BlockSize = 256;
                    fish.KeySize = 256;
                    fish.Padding = PaddingMode.None;
                    fish.Mode = CipherMode.ECB;
                    fish.SetTweak(tweak);
                    using (var dec = fish.CreateDecryptor(key, s_UnusedIV))
                    {
                        var data = dec.TransformFinalBlock(cipherTextBytes, offset, 0x20);
                        Buffer.BlockCopy(data, 0, plainTextBytes, offset, data.Length);
                    }
                    if (extratweak) tweak[1] += 0xC0;
                    tweak[0]++;
                }
            }
            // Remove all zeroes from the end of the plaintext.
            int len = plainTextBytes.Length;
            while (len > 0 && plainTextBytes[len - 1] == 0) len--;
            var ret = new byte[len];
            Buffer.BlockCopy(plainTextBytes, 0, ret, 0, len);
            return ret;
        }

        private static byte[] DecryptFish(string ciphertext, byte[] key, bool extratweak)
        {
            var cipherTextBytes = Convert.FromBase64String(ciphertext);
            return DecryptFish(cipherTextBytes, key, extratweak);
        }

        protected override string DecryptOuter(string ciphertext)
        {
            var bytes = XXTEA.Decrypt(DecryptAes(ciphertext, OuterKey, OuterIV), OuterKey);
            var rot = OuterRotate;
            if (rot != 0)
            {
                for (int i = 0; i < bytes.Length; i++) bytes[i] -= rot;
            }
            return Encoding.UTF8.GetString(bytes);
        }

        protected override string DecryptInner(string jsonKey, string ciphertext)
        {
            if (jsonKey == ServerNameKey || jsonKey == PortKey || jsonKey == CountryNameKey || jsonKey == OvpnKey || jsonKey == OvpnPortKey || jsonKey == V2rayUuidKey)
            {
                // AES + XXTEA
                return DecryptOuter(ciphertext);
            }
            else if (jsonKey == HostnameKey || jsonKey == V2rayHostKey || jsonKey == V2rayPathKey)
            {
                // Threefish + AES
                return Encoding.UTF8.GetString(DecryptAes(DecryptFish(ciphertext, InnerKeyFish, AdditionalTweak), InnerKeyAES, InnerIV));
            }
            else if (jsonKey == UsernameKey || jsonKey == PasswordKey)
            {
                if (ciphertext.Length == 0) return ciphertext;
                byte[] decode = null;
                // (Substitution cipher or base64) + XXTEA + AES
                if (IsSubstitution(ciphertext)) decode = DecodeSubstitution(ciphertext);
                else decode = Convert.FromBase64String(ciphertext);
                return DecryptAes(XXTEA.Decrypt(decode, InnerKey2), InnerKey2);
            }

            return ciphertext;
        }

        protected virtual IEnumerable<IVPNServer> ParseV2RayServer(string hostname, JsonElement server, JsonElement v2ray, Dictionary<string, string> extraRegistry)
        {
            string serverType = null;
            if (!v2ray.TryGetProperty(V2rayTypeKey, out var serverTypeJson)) throw new InvalidDataException();
            switch (serverTypeJson.ValueKind)
            {
                case JsonValueKind.String:
                    serverType = serverTypeJson.GetString();
                    break;
                case JsonValueKind.Number:
                    serverType = serverTypeJson.GetInt32().ToString();
                    break;
                default:
                    throw new InvalidDataException();
            }

            var parser = new RenzV2rayLinkParser();

            if (!v2ray.TryGetPropertyString(V2rayUuidKey, out var uuid)) throw new InvalidDataException();
            if (!v2ray.TryGetPropertyString(V2rayPathKey, out var path)) throw new InvalidDataException();
            if (!v2ray.TryGetPropertyString(V2rayHostKey, out var host)) throw new InvalidDataException();


            parser.id = uuid;
            parser.add = hostname;
            parser.port = "443";
            parser.host = host;
            parser.sni = "";
            parser.path = path;
            parser.tls = "tls";

            return V2RayServer.ParseConfigFull(parser.ConvertGeneric(serverType), extraRegistry);
        }

        protected override IEnumerable<IVPNServer> ParseServer(JsonDocument root, JsonElement server, IReadOnlyDictionary<string, string> passedExtraRegistry)
        {
            string serverType = null;
            if (!server.TryGetProperty(ServerTypeKey, out var serverTypeJson)) throw new InvalidDataException();
            switch (serverTypeJson.ValueKind)
            {
                case JsonValueKind.String:
                    serverType = serverTypeJson.GetString();
                    break;
                case JsonValueKind.Number:
                    serverType = serverTypeJson.GetInt32().ToString();
                    break;
                default:
                    throw new InvalidDataException();
            }

            string port;
            string username = null, password = null, ovpnconf = null;
            string name, country;

            if (!server.TryGetPropertyString(ServerNameKey, out name)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(CountryNameKey, out country)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(HostnameKey, out var hostnames)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(OvpnPortKey, out port)) throw new InvalidDataException();

            if (string.IsNullOrEmpty(hostnames)) throw new InvalidDataException();

            // if hostname contains semicolon then it's a list of hostnames
            // this fork also checks for comma and tilde as separators
            return hostnames.Split(';', ',', '~').SelectMany((hostname) =>
            {
                if (string.IsNullOrEmpty(hostname)) throw new InvalidDataException();
                var extraRegistry = new Dictionary<string, string>();
                foreach (var kv in passedExtraRegistry) extraRegistry.Add(kv.Key, kv.Value);
                extraRegistry.Add(ServerRegistryKeys.DisplayName, name);
                extraRegistry.Add(ServerRegistryKeys.Country, country);

                var protocolType = serverType.ToLower();
                if (protocolType == ProtocolTypeOvpn)
                {
                    if (!server.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(PasswordKey, out password)) throw new InvalidDataException();
                    if (string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password))
                    {
                        if (!root.RootElement.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                        if (!root.RootElement.TryGetPropertyString(PasswordKey, out password)) throw new InvalidDataException();
                        // Anything directly in the root is not yet decrypted:
                        username = DecryptInner(UsernameKey, username);
                        password = DecryptInner(PasswordKey, password);
                    }
                    if (!server.TryGetPropertyString(OvpnKey, out ovpnconf) || string.IsNullOrEmpty(ovpnconf))
                    {
                        if (root.RootElement.TryGetPropertyString(OvpnKey, out ovpnconf) && !string.IsNullOrEmpty(ovpnconf)) ovpnconf = DecryptInner(OvpnKey, ovpnconf);
                        else ovpnconf = OvpnConfTemplate.Replace("SERVERIPADDRESSHERE", hostname).Replace("0.0.0.0", hostname); // some samples use a template bundled inside the apk
                    }
                    if (string.IsNullOrEmpty(ovpnconf)) throw new InvalidDataException();
                    if (OvpnPortIsBogus)
                    {
                        // Port in the JSON object is bogus, the real port is in the openvpn config
                        var real = OpenVpnServer.ParseConfigFull(ovpnconf).FirstOrDefault();
                        if (real == null || !real.Registry.TryGetValue(ServerRegistryKeys.Port, out port)) throw new InvalidDataException();

                    }
                    var ovpnRegistry = new Dictionary<string, string>();
                    foreach (var kv in extraRegistry) ovpnRegistry.Add(kv.Key, kv.Value);
                    ovpnRegistry.Add(ServerRegistryKeys.Username, username);
                    ovpnRegistry.Add(ServerRegistryKeys.Password, password);
                    return OpenVpnServer.ParseConfigFull(OpenVpnServer.InjectHostIntoConfig(ovpnconf, hostname, port), ovpnRegistry);
                } else if (protocolType == ProtocolTypeSsh)
                {
                    if (!server.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(PasswordKey, out password)) throw new InvalidDataException();
                    if (string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password))
                    {
                        if (!root.RootElement.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                        if (!root.RootElement.TryGetPropertyString(PasswordKey, out password)) throw new InvalidDataException();
                        // Anything directly in the root is not yet decrypted:
                        username = DecryptInner(UsernameKey, username);
                        password = DecryptInner(PasswordKey, password);
                    }
                    // port may be bogus
                    if (port == "1194" || port == "143") port = "22";
                    return new SSHServer(hostname, port, username, password, extraRegistry).EnumerableSingle<IVPNServer>();
                } else if (protocolType == ProtocolTypeV2ray)
                {
                    if (!server.TryGetProperty(V2RayKey, out var v2ray) || v2ray.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                    return ParseV2RayServer(hostname, server, v2ray, extraRegistry);
                } else
                {
                    throw new InvalidDataException();
                }
            }).ToArray();
        }
    }

    public abstract class SocksHttpRenzParser2<TType> : SocksHttpRenzParser<TType>
        where TType : SocksHttpRenzParser2<TType>, new()
    {
        protected override byte[] OuterKey
        {
            get
            {
                using (var sha = new SHA256Managed())
                {
                    var hash = sha.ComputeHash(OuterKeyDerivation);
                    var ret = new byte[0x10];
                    Buffer.BlockCopy(hash, 0, ret, 0, 0x10);
                    return ret;
                }
            }
        }

        protected override bool AdditionalTweak => false;
    }

    // Subclass for the most common cryptoschemes used:
    public abstract class SocksHttpWithOvpnParserTea<TType> : SocksHttpWithOvpnParser<TType>
        where TType : SocksHttpWithOvpnParserTea<TType>, new()
    {
        protected virtual uint TeaDelta => 0x2E0BA747;

        private XXTEA XXTEA => XXTEA.Create(TeaDelta);

        protected abstract string OuterKey { get; }

        protected override string DecryptOuter(string ciphertext)
        {
            return XXTEA.DecryptBase64StringToString(ciphertext, OuterKey);
        }

        protected override string DecryptInner(string jsonKey, string ciphertext)
        {
            if (jsonKey != HostnameKey && jsonKey != UsernameKey && jsonKey != PasswordKey && jsonKey != OvpnKey && jsonKey != V2RayKey) return ciphertext;

            return Encoding.UTF8.GetString(Convert.FromBase64String(ciphertext));
        }
    }

    public abstract class SocksHttpWithOvpnParserAesGcmHkdf<TType> : SocksHttpWithOvpnParser<TType>
        where TType : SocksHttpWithOvpnParserAesGcmHkdf<TType>, new()
    {
        protected override string OvpnKey => "setOpenVPN";

        protected override string ServerNameKey => "ServerName";
        protected override string CountryNameKey => "ServerFlag";

        protected abstract string OuterKeyId { get; }
        protected virtual byte[] OuterKeySeed => "TVlfQVBQX0ZJWEVEX1NBTFRfVjE=".FromBase64String();
        protected virtual byte[] OuterKeyData => "TVlfU0VDVVJFX0pTT05fU1RSRUFNX1Yx".FromBase64String();
        protected virtual HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA256;
        protected virtual int PbkdfRounds => 100000;



        protected override string DecryptInner(string jsonKey, string ciphertext)
        {
            if (jsonKey != HostnameKey && jsonKey != UsernameKey && jsonKey != PasswordKey && jsonKey != OvpnKey && jsonKey != V2RayKey) return ciphertext;

            if (ciphertext.StartsWith("ED:")) return Encoding.UTF8.GetString(Base32Encoding.ToBytes(ciphertext.Substring(3)));

            return Encoding.UTF8.GetString(Convert.FromBase64String(ciphertext));
        }

        protected override string DecryptOuter(string ciphertext)
        {
            var bytes = Convert.FromBase64String(ciphertext);
            var iv = new byte[0x10];

            byte[] kek = null;
            using (var pbkdf2 = new Pbkdf2(OuterKeyId, OuterKeySeed, PbkdfRounds, HashAlgorithm))
                kek = pbkdf2.GetBytes(0x20);

            var gcmhkdf = new AesGcmHkdfStreaming(HashAlgorithmName.SHA256, 0x20, 0x1000);
            return Encoding.UTF8.GetString(gcmhkdf.Decrypt(kek, OuterKeyData, bytes));
        }
    }

    public abstract class SocksHttpWithOvpnNumericParserTea<TType> : SocksHttpWithOvpnNumericParser<TType>
        where TType : SocksHttpWithOvpnNumericParserTea<TType>, new()
    {
        protected virtual uint TeaDeltaOuter => 0x2E0BA747;
        protected virtual uint TeaDeltaInner => 0x2E0BA747;

        private XXTEA XXTEAOuter => XXTEA.Create(TeaDeltaOuter);
        private XXTEA XXTEAInner => XXTEA.Create(TeaDeltaInner);
        protected virtual string OuterKey => InnerKey.ToString();
        protected abstract int InnerKey { get; }

        protected override string DecryptOuter(string ciphertext)
        {
            return XXTEAOuter.DecryptBase64StringToString(ciphertext, OuterKey);
        }

        protected virtual string DecryptInner(string ciphertext)
        {
            var arr = XXTEAInner.DecryptBase64StringToString(ciphertext, InnerKey.ToString()).ToCharArray();
            for (int i = 0; i < arr.Length; i++) arr[i] -= (char)(InnerKey * 2);
            return new string(arr);
        }

        protected override string DecryptInner(string jsonKey, string ciphertext)
        {
            if (jsonKey == OvpnPortKey) return ciphertext.Split(':')[0];
            if (jsonKey != HostnameKey && jsonKey != UsernameKey && jsonKey != PasswordKey && jsonKey != OvpnKey && jsonKey != V2RayKey) return ciphertext;

            return DecryptInner(ciphertext);
        }
    }

    public abstract class SocksHttpWithOvpnNumericParserTeaOuter<TType> : SocksHttpWithOvpnNumericParserTea<TType>
        where TType : SocksHttpWithOvpnNumericParserTeaOuter<TType>, new()
    {
        protected override string DecryptOuter(string ciphertext)
        {
            return DecryptInner(ciphertext);
        }
    }

    public abstract class SocksHttpParserTeaAes<TType> : SocksHttpParser<TType>
        where TType : SocksHttpParserTeaAes<TType>, new()
    {
        protected virtual uint TeaDelta => 0x2E0BA747;

        private XXTEA XXTEA => XXTEA.Create(TeaDelta);

        protected abstract string OuterKey { get; }

        private static readonly byte[] s_InnerKey =
        {
            0x4a, 0xf9, 0xa1, 0x4a, 0xb6, 0xda, 0x0e, 0xfc,
            0xe7, 0x73, 0xf0, 0x1a, 0x02, 0x1c, 0xd5, 0x2e,
            0x67, 0x5d, 0xbb, 0xa1, 0x52, 0x84, 0xe5, 0x6b,
            0x57, 0x1d, 0xc1, 0xf5, 0x0e, 0xe2, 0x11, 0x76
        };

        private static readonly byte[] s_InnerIv = new byte[0x10];

        protected override string DecryptOuter(string ciphertext)
        {
            return XXTEA.DecryptBase64StringToString(ciphertext, OuterKey);
        }

        protected override string DecryptInner(string jsonKey, string ciphertext)
        {
            if (jsonKey != HostnameKey && jsonKey != UsernameKey && jsonKey != PasswordKey && jsonKey != V2RayKey) return ciphertext;

            var cipherTextBytes = Convert.FromBase64String(ciphertext);
            using (var aes = new AesManaged())
            {
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Padding = PaddingMode.PKCS7;
                using (var dec = aes.CreateDecryptor(s_InnerKey, s_InnerIv))
                {
                    return Encoding.UTF8.GetString(dec.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length));
                }
            }
        }
    }

    public abstract class SocksHttpParserAes<TType> : SocksHttpParser<TType>
        where TType : SocksHttpParserAes<TType>, new()
    {
        protected abstract byte[] OuterKey { get; }

        private static readonly byte[] s_InnerKey =
        {
            0x4a, 0xf9, 0xa1, 0x4a, 0xb6, 0xda, 0x0e, 0xfc,
            0xe7, 0x73, 0xf0, 0x1a, 0x02, 0x1c, 0xd5, 0x2e,
            0x67, 0x5d, 0xbb, 0xa1, 0x52, 0x84, 0xe5, 0x6b,
            0x57, 0x1d, 0xc1, 0xf5, 0x0e, 0xe2, 0x11, 0x76
        };

        private static readonly byte[] s_AesIv = new byte[0x10];

        private static string DecryptAes(string ciphertext, byte[] key)
        {
            var cipherTextBytes = Convert.FromBase64String(ciphertext);
            using (var aes = new AesManaged())
            {
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Padding = PaddingMode.PKCS7;
                using (var dec = aes.CreateDecryptor(key, s_AesIv))
                {
                    return Encoding.UTF8.GetString(dec.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length));
                }
            }
        }

        protected override string DecryptOuter(string ciphertext)
        {
            return DecryptAes(ciphertext, OuterKey);
        }

        protected override string DecryptInner(string jsonKey, string ciphertext)
        {
            if (jsonKey != HostnameKey && jsonKey != UsernameKey && jsonKey != PasswordKey && jsonKey != V2RayKey) return ciphertext;

            return DecryptAes(ciphertext, s_InnerKey);
        }
    }

    public abstract class SocksHttpParserAesPbkdf2<TType> : SocksHttpParser<TType>
        where TType : SocksHttpParserAesPbkdf2<TType>, new()
    {
        protected abstract string OuterKeyId { get; }
        protected virtual HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA256;
        protected virtual int PbkdfRounds => 10000;

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
    }
}
