using System;
using System.Collections.Generic;
using System.Text;
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
        protected override string RequestUri => string.Format("https://raw.githubusercontent.com/{0}/{1}/{2}", RepoName, BranchName, ConfigName);

        public override bool RiskyRequests => false;
    }

    public abstract class VPNProviderGithubRepoFileBase<TParser> : VPNProviderGithubRepoFileBase
        where TParser : VPNGenericMultiProviderParser<TParser>, new()
    {
        protected override Task<IEnumerable<IVPNServer>> GetServersAsyncImpl(string config)
            => GetServersAsyncImpl<TParser>(config);
    }
}
