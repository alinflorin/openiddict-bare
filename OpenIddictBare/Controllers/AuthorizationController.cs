using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Authentication.Twitter;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddictBare.Models;

namespace OpenIddictBare.Controllers
{
    public class AuthorizationController : Controller
    {
        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo")]
        public async Task<IActionResult> Userinfo()
        {
            var claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

            return Ok(claimsPrincipal.Claims.Select(x => new { 
                Key = x.Type,
                x.Value
            }).ToList());
        }

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            ClaimsPrincipal claimsPrincipal;

            if (request.IsClientCredentialsGrantType())
            {
                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId ?? throw new InvalidOperationException());
                claimsPrincipal = new ClaimsPrincipal(identity);
                claimsPrincipal.SetScopes(request.GetScopes());
                claimsPrincipal.SetResources(request.Resources != null && request.Resources.Any() ? request.Resources[0] : request.ClientId);
            }

            else if (request.IsAuthorizationCodeGrantType())
            {
                claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
            }

            else if (request.IsRefreshTokenGrantType())
            {
                // Retrieve the claims principal stored in the refresh token.
                claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
            }
            else
            {
                throw new InvalidOperationException("The specified grant type is not supported.");
            }

            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (!request.HasParameter("provider") || !request.GetParameter("provider").HasValue)
            {
                var location = new Uri($"{Request.Scheme}://{Request.Host}{Request.Path}{Request.QueryString}");
                var url = location.AbsoluteUri;
                var html = Templates.RenderTemplate(
                    new[] { "google", "facebook", "microsoft", "github" },
                    url
                );
                return new ContentResult
                {
                    Content = html,
                    ContentType = "text/html",
                    StatusCode = 200
                };
            }
            var provider = request.GetParameter("provider").Value.ToString();

            // Retrieve the user principal stored in the authentication cookie.
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        
            // If the user principal can't be extracted, redirect the user to the login page.
            if (!result.Succeeded)
            {
                return Challenge(
                    authenticationSchemes: new[] { MapProviderToScheme(provider) });
            }


            // Create a new claims principal
            var claims = GetClaims(result.Principal, provider);
        
            var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
        
            // Set requested scopes (this is not done automatically)
            claimsPrincipal.SetScopes(request.GetScopes());
        
            // Signing in with the OpenIddict authentiction scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        private static IEnumerable<Claim> GetClaims(ClaimsPrincipal principal, object provider)
        {
            switch (provider)
            {
                default:
                    throw new InvalidOperationException("Unknown provider");

                case "google":
                    return new List<Claim>
                    {
                        new Claim(OpenIddictConstants.Claims.Subject, principal.Identity.Name)
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken),
                        new Claim(OpenIddictConstants.Claims.Email, principal.FindFirstValue(ClaimTypes.Email))
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken)
                    };
                case "facebook":
                    return new List<Claim>
                    {
                        new Claim(OpenIddictConstants.Claims.Subject, principal.Identity.Name)
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken),
                        new Claim(OpenIddictConstants.Claims.Email, principal.FindFirstValue(ClaimTypes.Email))
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken)
                    };
                case "github":
                    return new List<Claim>
                    {
                        new Claim(OpenIddictConstants.Claims.Subject, principal.Identity.Name)
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken),
                        new Claim(OpenIddictConstants.Claims.Email, principal.FindFirstValue(ClaimTypes.Email))
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken)
                    };
                case "twitter":
                    return new List<Claim>
                    {
                        new Claim(OpenIddictConstants.Claims.Subject, principal.Identity.Name)
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken),
                        new Claim(OpenIddictConstants.Claims.Email, principal.FindFirstValue(ClaimTypes.Email))
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken)
                    };
                case "microsoft":
                    return new List<Claim>
                    {
                        new Claim(OpenIddictConstants.Claims.Subject, principal.Identity.Name)
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken),
                        new Claim(OpenIddictConstants.Claims.Email, principal.FindFirstValue(ClaimTypes.Email))
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken)
                    };
            }
        }

        private static string MapProviderToScheme(string provider)
        {
            switch (provider)
            {
                default:
                    throw new InvalidOperationException("Unknown provider");
                case "google":
                    return GoogleDefaults.AuthenticationScheme;
                case "facebook":
                    return FacebookDefaults.AuthenticationScheme;
                case "github":
                    return "GitHub";
                case "twitter":
                    return TwitterDefaults.AuthenticationScheme;
                case "microsoft":
                    return MicrosoftAccountDefaults.AuthenticationScheme;
            }
        }
    }
}
