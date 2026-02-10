using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibFreeVPN
{
    public abstract class VPNProviderBase : IVPNProvider
    {
        public virtual string Name => GetType().Name;
        public abstract string SampleSource { get; }
        public abstract string SampleVersion { get; }
        public abstract bool RiskyRequests { get; }

        public virtual DateTime? PossiblyAbandoned => null;

        public abstract bool HasProtocol(ServerProtocol protocol);

        protected abstract Task<IEnumerable<IVPNServer>> GetServersAsyncImpl();

        public async Task<IEnumerable<IVPNServer>> GetServersAsync()
        {
            try
            {
                return await GetServersAsyncImpl();
            }
            catch
            {
                return Enumerable.Empty<IVPNServer>();
            }
        }

        protected Dictionary<string, string> CreateExtraRegistry()
        {
            return new Dictionary<string, string>()
            {
                { ServerRegistryKeys.ProviderName, Name }
            };
        }

        protected static Dictionary<string, string> CreateExtraRegistry(string name)
        {
            return new Dictionary<string, string>()
            {
                { ServerRegistryKeys.ProviderName, name }
            };
        }
    }
}
