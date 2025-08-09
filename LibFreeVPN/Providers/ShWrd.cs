using LibFreeVPN.Memecrypto;
using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

// Android apps. SocksHttp using SSH + OpenVPN
// All of these by same developer, same github repo used, same xxtea constant, differs only in xxtea keys.
// Original apps use cname to github pages, this implementation hits the repo directly.
namespace LibFreeVPN.Providers.ShWrd
{
    public abstract class ParserBaseOvpn<TType> : SocksHttpWithOvpnParser<TType>
        where TType : ParserBaseOvpn<TType>, new()
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

    public abstract class ParserBase<TType> : SocksHttpParser<TType>
        where TType : ParserBase<TType>, new()
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


    public abstract class ShWrdBase<TParser> : VPNProviderBase
        where TParser : SocksHttpParser<TParser>, new()
    {

        protected virtual string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("RmlsZS5qc29u"));

        public override bool RiskyRequests => false;

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH || protocol == ServerProtocol.OpenVPN || protocol == ServerProtocol.V2Ray;



        protected virtual string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("aHVubWFpL3dhcnJpbmdkYQ=="));



        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = new HttpClient();
            // Get the single config file used here.
            var config = await httpClient.GetStringAsync(string.Format("https://raw.githubusercontent.com/{0}/main/{1}", RepoName, ConfigName));

            // And try to parse it
            var extraRegistry = CreateExtraRegistry(Name);
            return SocksHttpParser<TParser>.ParseConfig(config, extraRegistry);
        }
    }

    public sealed class ShWrdPk : ShWrdBase<ShWrdPk.Parser>
    {
        public sealed class Parser : ParserBaseOvpn<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("cHVrYW5ndnBuMjcwQA=="));
        }
        public override string Name => nameof(ShWrdPk);

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5wdWthbmd2cG4udGg=";

        public override string SampleVersion => "7.4";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("cHVrYW5ndnBuL3VwLWZpbGUuanNvbg=="));
    }

    public sealed class ShWrdKh : ShWrdBase<ShWrdKh.Parser>
    {
        public sealed class Parser : ParserBase<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("a2hhbXZwbjI3MEA="));
        }
        public override string Name => nameof(ShWrdKh);

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5oa2FtdnBuLm5ldA==";

        public override string SampleVersion => "14.0";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("a2hhbXZwbi91cGRhdGUtZmlsZS5qc29u"));
    }

    public sealed class ShWrdMt : ShWrdBase<ShWrdMt.Parser>
    {
        public sealed class Parser : ParserBaseOvpn<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("bXR2cG4yNUA="));
        }
        public override string Name => nameof(ShWrdMt);

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5tdHZwbi5tdHZwbg==";

        public override string SampleVersion => "2.2";

        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("aHVubWFpL01ULVZQTg=="));
    }
}
