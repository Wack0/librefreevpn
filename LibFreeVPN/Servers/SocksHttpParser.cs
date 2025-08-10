using LibFreeVPN.Memecrypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
                    if (!server.TryGetPropertyString(OvpnKey, out ovpnconf))
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

    // Subclass for the most common cryptoschemes used:
    public abstract class SocksHttpWithOvpnParserTea<TType> : SocksHttpWithOvpnParser<TType>
        where TType : SocksHttpWithOvpnParserTea<TType>, new()
    {
        private static readonly XXTEA s_XXTEA = new XXTEA(0x2E0BA747);

        protected abstract string OuterKey { get; }

        protected override string DecryptOuter(string ciphertext)
        {
            return s_XXTEA.DecryptBase64StringToString(ciphertext, OuterKey);
        }

        protected override string DecryptInner(string jsonKey, string ciphertext)
        {
            if (jsonKey != HostnameKey && jsonKey != UsernameKey && jsonKey != PasswordKey && jsonKey != OvpnKey && jsonKey != V2RayKey) return ciphertext;

            return Encoding.UTF8.GetString(Convert.FromBase64String(ciphertext));
        }
    }

    public abstract class SocksHttpParserTeaAes<TType> : SocksHttpParser<TType>
        where TType : SocksHttpParserTeaAes<TType>, new()
    {
        private static readonly XXTEA s_XXTEA = new XXTEA(0x2E0BA747);

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
            return s_XXTEA.DecryptBase64StringToString(ciphertext, OuterKey);
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
}
