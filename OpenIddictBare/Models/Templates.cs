using Microsoft.AspNetCore.WebUtilities;

namespace OpenIddictBare.Models
{
    public static class Templates
    {
        public static string LoginTemplate { get; set; }

        public static string RenderTemplate(string[] providers, string link) {
            var linksHtml = "";
            foreach (var provider in providers) {
                var linkWithProvider = QueryHelpers.AddQueryString(link, "provider", provider);
                linksHtml += $"<a class=\"cap\" href=\"{linkWithProvider}\"><i class=\"fa fa-{(provider == "microsoft" ? "windows" : provider)}\"></i>{provider}</a>";
            }
            return LoginTemplate.Replace("{{links}}", linksHtml);
        }
    }
}
