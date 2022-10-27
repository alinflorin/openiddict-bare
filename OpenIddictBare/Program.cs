using dotenv.net;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using OpenIddictBare;
using OpenIddictBare.Models;

var path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "/idp.env";
DotEnv.Load(options: new DotEnvOptions(ignoreExceptions: true, envFilePaths: new[] { path }, overwriteExistingVars: false));

Templates.LoginTemplate = File.ReadAllText("login.html");

var builder = WebApplication.CreateBuilder(args);


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

builder.Services.AddDbContext<DbContext>(options =>
{
    // Configure the context to use an in-memory store.
    options.UseInMemoryDatabase(nameof(DbContext));

    // Register the entity sets needed by OpenIddict.
    options.UseOpenIddict();
});

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        // Configure OpenIddict to use the EF Core stores/models.
        options.UseEntityFrameworkCore()
            .UseDbContext<DbContext>();
    })
    .AddServer(options =>
    {
        options.SetIssuer(new Uri(builder.Configuration["Issuer"]));
        options.AddEphemeralEncryptionKey().AddEphemeralSigningKey();
        options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
        options.SetAuthorizationEndpointUris("/connect/authorize")
                .SetUserinfoEndpointUris("/connect/userinfo")
               .SetTokenEndpointUris("/connect/token");
        options.AllowClientCredentialsFlow();
        options.AllowRefreshTokenFlow();
        options.DisableAccessTokenEncryption();
        options.AllowRefreshTokenFlow();
        options.UseAspNetCore()
        .EnableTokenEndpointPassthrough()
        .EnableUserinfoEndpointPassthrough()
        .EnableAuthorizationEndpointPassthrough()
        .DisableTransportSecurityRequirement();

        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(builder.Configuration.GetValue<int>("AccessTokenLifetimeMinutes")));
        options.SetIdentityTokenLifetime(TimeSpan.FromMinutes(builder.Configuration.GetValue<int>("IdentityTokenLifetimeMinutes")));
        options.SetRefreshTokenLifetime(TimeSpan.FromMinutes(builder.Configuration.GetValue<int>("RefreshTokenLifetimeMinutes")));

        options.RegisterScopes(builder.Configuration.GetSection("Scopes").Get<string[]>());
    });

builder.Services.AddHostedService<OpenIddictHostedService>();



var app = builder.Build();

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
});

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.UseEndpoints(x =>
{
    x.MapControllers();
});

app.Run();
