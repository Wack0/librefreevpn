using LibFreeVPN.Memecrypto;
using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

// Android apps. SocksHttp using SSH + OpenVPN + V2Ray.
// All of these by same developer, same github repo used, same xxtea constant, differs only in xxtea keys.
namespace LibFreeVPN.Providers.ShNo
{
    public abstract class ShNoBase<TParser> : VPNProviderBase
        where TParser : SocksHttpWithOvpnParserTea<TParser>, new()
    {
        
        protected abstract string ConfigName { get; }

        public override bool RiskyRequests => false;

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH || protocol == ServerProtocol.OpenVPN || protocol == ServerProtocol.V2Ray;

        private static readonly string s_RepoName = Encoding.ASCII.GetString(Convert.FromBase64String("QW51cmFrMjUzNC9vaG12cG4="));



        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = new HttpClient();
            // Get the single config file used here.
            var config = await httpClient.GetStringAsync(string.Format("https://raw.githubusercontent.com/{0}/main/{1}", s_RepoName, ConfigName));

            // And try to parse it
            var extraRegistry = CreateExtraRegistry();
            return SocksHttpWithOvpnParserTea<TParser>.ParseConfig(config, extraRegistry);
        }
    }

    public sealed class ShNoo : ShNoBase<ShNoo.Parser>
    {
        public sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("b2htMDkwNTI5"));
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS53aWxsYmVhbG9uZS5vaG12cG4=";

        public override string SampleVersion => "4.5";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("b2htLmpzb24="));
    }

    public sealed class ShNosa : ShNoBase<ShNosa.Parser>
    {
        public sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("c2F0aHUyMDA1MzA="));
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5wdWJsaWNzZXJ2aWNlc3NoLnNhdGh1dnBu";

        public override string SampleVersion => "2.5";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("c2F0aHUuanNvbg=="));
    }

    public sealed class ShNona : ShNoBase<ShNona.Parser>
    {
        public sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("bmFtbzA5MDUyOQ=="));
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5hcHB4cmF5c2VydmljZS5uYW1vdnBu";

        public override string SampleVersion => "2.5";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("bmFtby5qc29u"));
    }

    public sealed class ShNogo : ShNoBase<ShNogo.Parser>
    {
        public sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
        {
            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("Z29vZHZwbjA5MDUyOQ=="));
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5vdnBuc2V2aWNlLmdvb2R2cG4=";

        public override string SampleVersion => "2.5";

        protected override string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("Z29vZHZwbi5qc29u"));
    }
}
