namespace Maliev.AuthService.Api.Services
{
    public class ExternalAuthServiceHttpClient
    {
        public virtual HttpClient Client { get; }

        public ExternalAuthServiceHttpClient(HttpClient httpClient)
        {
            Client = httpClient;
        }
    }
}