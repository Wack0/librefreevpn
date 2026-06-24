using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace LibFreeVPN.ProviderHelpers
{
    public abstract class VPNProviderHttpGetBase : VPNProviderBase
    {
        public override bool RiskyRequests => true;
        protected abstract string RequestUri { get; }
        protected abstract Task<IEnumerable<IVPNServer>> GetServersAsyncImpl(string config);

        protected Task<IEnumerable<IVPNServer>> GetServersAsyncImpl<TParser>(string config)
            where TParser : VPNGenericMultiProviderParser<TParser>, new()
        {
            var extraRegistry = CreateExtraRegistry();
            return Task.FromResult(VPNGenericMultiProviderParser<TParser>.ParseConfig(config, extraRegistry));
        }

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var config = await ServerUtilities.HttpClient.GetStringAsync(RequestUri);
            return await GetServersAsyncImpl(config);
        }
    }

    public abstract class VPNProviderHttpGetBase<TParser> : VPNProviderHttpGetBase
        where TParser : VPNGenericMultiProviderParser<TParser>, new()
    {
        protected override Task<IEnumerable<IVPNServer>> GetServersAsyncImpl(string config)
            => GetServersAsyncImpl<TParser>(config);
    }

    public abstract class VPNProviderGithubRepoFileBase : VPNProviderHttpGetBase
    {
        protected abstract string RepoName { get; }
        protected virtual string BranchName => "main";
        protected abstract string ConfigName { get; }

        private static string RequestUriGetter(VPNProviderGithubRepoFileBase self)
            => string.Format("https://raw.githubusercontent.com/{0}/{1}/{2}", self.RepoName, self.BranchName, self.ConfigName);
        protected override string RequestUri => this.SingleInstanceByType(RequestUriGetter);

        public override bool RiskyRequests => false;
    }

    public abstract class VPNProviderGithubRepoFileBase<TParser> : VPNProviderGithubRepoFileBase
        where TParser : VPNGenericMultiProviderParser<TParser>, new()
    {
        protected override Task<IEnumerable<IVPNServer>> GetServersAsyncImpl(string config)
            => GetServersAsyncImpl<TParser>(config);
    }

    public abstract class VPNProviderGithubRepoFilesBase : VPNProviderBase
    {
        protected abstract string RepoName { get; }
        protected virtual string BranchName => "main";

        private static string RequestUriGetter(VPNProviderGithubRepoFilesBase self)
            => string.Format("https://github.com/{0}/tree-commit-info/{1}", self.RepoName, self.BranchName);
        protected string RequestUri => this.SingleInstanceByType(RequestUriGetter);

        public override bool RiskyRequests => false;

        private static string SingleRequestUriBaseGetter(VPNProviderGithubRepoFilesBase self)
            => string.Format("https://raw.githubusercontent.com/{0}/{1}/", self.RepoName, self.BranchName);

        protected string SingleRequestUriBase => this.SingleInstanceByType(SingleRequestUriBaseGetter);
        protected string RequestUriGetter(string filename)
            => new StringBuilder(SingleRequestUriBase).Append(filename).ToString();

        protected abstract Task<IEnumerable<IVPNServer>> GetServersAsyncImpl(IEnumerable<string> files);

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = ServerUtilities.HttpClient;
            // Get the list of files in the root of the repository
            HttpResponseMessage listResponse = null;
            using (var listRequest = new HttpRequestMessage(HttpMethod.Get, RequestUri))
            {
                listRequest.Headers.Accept.ParseAdd("application/json");
                listResponse = await httpClient.SendAsync(listRequest);
            }
            var listJsonStr = await listResponse.Content.ReadAsStringAsync();
            var listJson = JsonDocument.Parse(listJsonStr);
            if (listJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            // take the filenames we want, convert them to their URLs
            var configFiles = listJson.RootElement.GetProperty("entries").EnumerateObject().Select((obj) => obj.Name);
            return await GetServersAsyncImpl(configFiles);
        }
    }
}
