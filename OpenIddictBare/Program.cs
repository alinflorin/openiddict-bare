using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using OpenIddictBare.Models;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using Microsoft.AspNetCore.Authentication.Google;
using OpenIddict.Abstractions;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using AspNet.Security.OAuth.GitHub;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

var idpClients = builder.Configuration.GetSection("Clients").Get<IEnumerable<IdpClient>>();
if (idpClients == null)
{
    throw new Exception("No clients have been configured!");
}

builder.Services.AddControllers();

var authBuilder = builder.Services.AddAuthentication()
        .AddCookie();

if (builder.Configuration["Facebook:ClientId"] != null && builder.Configuration["Facebook:ClientSecret"] != null)
{
    authBuilder = authBuilder.AddFacebook(options =>
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.AppId = builder.Configuration["Facebook:ClientId"];
        options.AppSecret = builder.Configuration["Facebook:ClientSecret"];
    });
}

if (builder.Configuration["Google:ClientId"] != null && builder.Configuration["Google:ClientSecret"] != null)
{
    authBuilder = authBuilder.AddGoogle(options =>
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ClientId = builder.Configuration["Google:ClientId"];
        options.ClientSecret = builder.Configuration["Google:ClientSecret"];
    });
}

if (builder.Configuration["Microsoft:ClientId"] != null && builder.Configuration["Microsoft:ClientSecret"] != null)
{
    authBuilder = authBuilder.AddMicrosoftAccount(options =>
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ClientId = builder.Configuration["Microsoft:ClientId"];
        options.ClientSecret = builder.Configuration["Microsoft:ClientSecret"];
    });
}

if (builder.Configuration["Twitter:ClientId"] != null && builder.Configuration["Twitter:ClientSecret"] != null)
{
    authBuilder = authBuilder.AddTwitter(options =>
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ConsumerKey = builder.Configuration["Twitter:ClientId"];
        options.ConsumerSecret = builder.Configuration["Twitter:ClientSecret"];
    });
}

if (builder.Configuration["GitHub:ClientId"] != null && builder.Configuration["GitHub:ClientSecret"] != null)
{
    authBuilder = authBuilder.AddGitHub(o =>
    {
        o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.ClientId = builder.Configuration["GitHub:ClientId"];
        o.ClientSecret = builder.Configuration["GitHub:ClientSecret"];
        o.CallbackPath = "/signin-github";
        o.Scope.Add("read:user");
    });
}

builder.Services.AddOpenIddict()
    .AddServer(options =>
    {
        options
                .AddDevelopmentEncryptionCertificate()
                .AddDevelopmentSigningCertificate();
        options.AllowAuthorizationCodeFlow();
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token");
        options.EnableDegradedMode();
        options.AllowClientCredentialsFlow();
        options.DisableAccessTokenEncryption();
        options.AllowRefreshTokenFlow();
        options.AllowImplicitFlow();
        options.UseAspNetCore().DisableTransportSecurityRequirement();


        options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                if (!idpClients.Any(idpc => string.Equals(context.ClientId, idpc.ClientId, StringComparison.Ordinal)))
                {
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: "The specified 'client_id' doesn't match a registered application.");
                    return default;
                }
                
                if (context.RedirectUri == null || !idpClients.Any(idpc => idpc.RedirectUrls != null && idpc.RedirectUrls.Any(ru => string.Equals(ru, context.RedirectUri))))
                {
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: "The specified 'redirect_uri' is not valid for this client application.");
                    return default;
                }
                return default;
            }));
        options.AddEventHandler<ValidateTokenRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                if (!idpClients.Any(idpc => string.Equals(context.ClientId, idpc.ClientId, StringComparison.Ordinal)))
                {
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: "The specified 'client_id' doesn't match a registered application.");
                    return default;
                }

                if (context.Request.GrantType == "client_credentials")
                {

                    if (!idpClients.Any(idpc => string.Equals(context.ClientSecret, idpc.ClientSecret, StringComparison.Ordinal)))
                    {
                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The specified 'client_secret' doesn't match a registered application.");
                        return default;
                    }
                }

                return default;
            }));

        options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
        {
            builder.UseInlineHandler(async context =>
            {
                if (!context.Request.HasParameter("provider") || !context.Request.GetParameter("provider").HasValue)
                {
                    context.SkipRequest();
                    return;
                }
                var provider = context.Request.GetParameter("provider").Value.ToString();

                var request = context.Transaction.GetHttpRequest() ??
                    throw new InvalidOperationException("The ASP.NET Core request cannot be retrieved.");
                var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);

                switch (provider)
                {
                    default:
                        context.SkipRequest();
                        return;
                    case "google":
                        var principal = (await request.HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme))?.Principal;
                        if (principal == null)
                        {
                            await request.HttpContext.ChallengeAsync(GoogleDefaults.AuthenticationScheme);
                            context.HandleRequest();
                            return;
                        }
                        identity.AddClaim(new Claim(Claims.Subject, principal.GetClaim(ClaimTypes.NameIdentifier)));
                        identity.AddClaim(new Claim(Claims.Email, principal.GetClaim(ClaimTypes.Email)));
                        foreach (var claim in identity.Claims)
                        {
                            claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                        }
                        break;
                }
                context.Principal = new ClaimsPrincipal(identity);
            });
        });
    })
    .AddValidation(options =>
    {
        options.UseLocalServer(x => {
        
        });
        options.UseAspNetCore(x => { 
            
        });
    });

var app = builder.Build();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.UseEndpoints(x =>
{
    x.MapControllers();
});

app.Run();
