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
        public sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
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
        public sealed class Parser : SocksHttpParserTeaAes<Parser>
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
        public sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("bXR2cG4yNUA="));
        }
        public override string Name => nameof(ShWrdMt);

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5tdHZwbi5tdHZwbg==";

        public override string SampleVersion => "2.2";

        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("aHVubWFpL01ULVZQTg=="));
    }
}
