namespace OpenIddictBare.Models
{
    public class IdpClient
    {
        public string Name { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public IEnumerable<string> RedirectUrls { get; set; }
        public bool IsPublic { get; set; }
    }
}
