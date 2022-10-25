namespace OpenIddictBare.Models
{
    public class IdpClient
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public IEnumerable<string> RedirectUrls { get; set; }
    }
}
