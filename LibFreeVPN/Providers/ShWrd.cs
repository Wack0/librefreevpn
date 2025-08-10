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
// All of these by same developer.
// Original apps use cname to github pages, this implementation hits the repo directly.
namespace LibFreeVPN.Providers.ShWrd
{
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
            var extraRegistry = CreateExtraRegistry();
            return SocksHttpParser<TParser>.ParseConfig(config, extraRegistry);
        }
    }

    public sealed class ShWrdPk : ShWrdBase<ShWrdPk.Parser>
    {
        public sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("cHVrYW5ndnBuMjcwQA=="));
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5wdWthbmd2cG4udGg=";

        public override string SampleVersion => "7.4";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("cHVrYW5ndnBuL3VwLWZpbGUuanNvbg=="));
    }

    public sealed class ShWrdKh : ShWrdBase<ShWrdKh.Parser>
    {
        public sealed class Parser : SocksHttpParserTeaAes<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("a2hhbXZwbjI3MEA="));
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5oa2FtdnBuLm5ldA==";

        public override string SampleVersion => "14.0";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("a2hhbXZwbi91cGRhdGUtZmlsZS5qc29u"));
    }

    public sealed class ShWrdMt : ShWrdBase<ShWrdMt.Parser>
    {
        public sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("bXR2cG4yNUA="));
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5tdHZwbi5tdHZwbg==";

        public override string SampleVersion => "2.2";

        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("aHVubWFpL01ULVZQTg=="));
    }

    public sealed class ShWrdErr : ShWrdBase<ShWrdErr.Parser>
    {
        public sealed class Parser : SocksHttpParserAes<Parser>
        {
            protected override byte[] OuterKey => new byte[] {
                0xd2, 0x25, 0x9f, 0xcd, 0x59, 0x94, 0xa1, 0xb4,
                0x8c, 0x90, 0x2c, 0xf0, 0x55, 0x3c, 0x85, 0x7c,
                0xb8, 0xd8, 0x35, 0x4b, 0x40, 0x07, 0xbc, 0x4f,
                0xbf, 0xdc, 0x80, 0x6b, 0x08, 0xa9, 0x1e, 0xc9
            };
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5tdHZwbi5tdHZwbg==";

        public override string SampleVersion => "2.2";

        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("RVJST1ItVlBOL2Vycm9yLXZwbi5naXRodWIuaW8="));

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("Y29uZmlnLmpzb24="));
    }

    public sealed class ShWrdPnt : ShWrdBase<ShWrdPnt.Parser>
    {
        public sealed class Parser : SocksHttpWithOvpnNumericParserTea<Parser>
        {
            protected override string ServerTypeKey => "Category";
            protected override uint TeaDeltaOuter => 0xD1FBFA0B;
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("Y29tLnBudHZwbi5uZXQubQ=="));
            protected override int InnerKey => 7376;
            protected override bool OvpnPortIsBogus => true;

            protected override string DecryptInner(string jsonKey, string ciphertext)
            {
                if (jsonKey == OvpnPortKey) return ciphertext.Split(':')[0];
                if (jsonKey != HostnameKey && jsonKey != UsernameKey && jsonKey != PasswordKey && jsonKey != V2RayKey) return ciphertext;

                return DecryptInner(ciphertext);
            }
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5wbnR2cG4ubmV0";

        public override string SampleVersion => "1.0.5";

        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("c2Fuc29lMjAyMi9QTlRfVlBO"));

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("Y29uZmlnLmZpbGU="));
    }
}
