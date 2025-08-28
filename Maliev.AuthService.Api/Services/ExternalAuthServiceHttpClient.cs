namespace Maliev.AuthService.Api.Services
{
    public class ExternalAuthServiceHttpClient
    {
        public HttpClient Client { get; }

        public ExternalAuthServiceHttpClient(HttpClient httpClient)
        {
            Client = httpClient;
        }
    }
}