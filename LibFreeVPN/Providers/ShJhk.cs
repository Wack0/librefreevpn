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

// Android apps. SocksHttp using SSH + OpenVPN.
// All of these by same developer, same github account used, xxtea + custom unicode rot.
namespace LibFreeVPN.Providers.ShJhk
{
    public abstract class ParserBase<TType> : SocksHttpWithOvpnNumericParserTea<TType>
        where TType : ParserBase<TType>, new()
    {
        protected override string DecryptOuter(string ciphertext)
        {
            return DecryptInner(ciphertext);
        }
    }
    public sealed class Parser4669 : ParserBase<Parser4669>
    {
        protected override int InnerKey => 4669;
    }

    public abstract class ShJhkBase<TParser> : VPNProviderBase
        where TParser : ParserBase<TParser>, new()
    {

        protected virtual string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("dXBkYXRlcw=="));
        protected abstract string RepoName { get; }

        public override bool RiskyRequests => false;

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH || protocol == ServerProtocol.OpenVPN;



        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = new HttpClient();
            // Get the single config file used here.
            var config = await httpClient.GetStringAsync(string.Format("https://raw.githubusercontent.com/{0}/main/{1}", RepoName, ConfigName));

            // And try to parse it
            var extraRegistry = CreateExtraRegistry();
            return ParserBase<TParser>.ParseConfig(config, extraRegistry);
        }
    }

    public sealed class ShJk : ShJhkBase<Parser4669>
    {
        
        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("SkhLVlBOL0pL"));

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5mYXN0dnBuLmpr";

        public override string SampleVersion => "2.2";

        public override bool RiskyRequests => false;
    }

    public sealed class ShJkV : ShJhkBase<Parser4669>
    {
        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("SkhLVlBOL0pWUE5WSVA="));

        public override string SampleSource => "aHR0cHM6Ly9naXRodWIuY29tL1RIQU5EQVJMSU4yMDE1L1Rlc3QvcmVsZWFzZXMvZG93bmxvYWQvdjIuMC4wL0pLLlZJUC5WUE5fMi4wLjAuYXBr";

        public override string SampleVersion => "2.0.0";

        public override bool RiskyRequests => false;
    }

    public sealed class ShMmt : ShJhkBase<Parser4669>
    {
        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("SkhLVlBOL01NVFZQTg=="));

        // No sample found - saw in repo list and observed to use the same memecrypto as the others here
        public override string SampleSource => "aHR0cHM6Ly9naXRodWIuY29tL0pIS1ZQTi9NTVRWUE4=";

        public override string SampleVersion => "N/A";

        public override bool RiskyRequests => false;
    }

    public sealed class ShKo : ShJhkBase<Parser4669>
    {
        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("SkhLVlBOL0tPS08="));

        // No sample found - saw in repo list and observed to use the same memecrypto as the others here
        public override string SampleSource => "aHR0cHM6Ly9naXRodWIuY29tL0pIS1ZQTi9LT0tP";

        public override string SampleVersion => "N/A";

        public override bool RiskyRequests => false;
    }
}
