using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

var authBuilder = builder.Services.AddAuthentication()
        .AddCookie();

if (builder.Configuration["Facebook:ClientId"] != null && builder.Configuration["Facebook:ClientSecret"] != null)
{
    authBuilder.AddFacebook(options =>
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.AppId = builder.Configuration["Facebook:ClientId"];
        options.AppSecret = builder.Configuration["Facebook:ClientSecret"];
    });
}

if (builder.Configuration["Google:ClientId"] != null && builder.Configuration["Google:ClientSecret"] != null)
{
    authBuilder.AddGoogle(options =>
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ClientId = builder.Configuration["Google:ClientId"];
        options.ClientSecret = builder.Configuration["Google:ClientSecret"];
    });
}

if (builder.Configuration["Microsoft:ClientId"] != null && builder.Configuration["Microsoft:ClientSecret"] != null)
{
    authBuilder.AddMicrosoftAccount(options =>
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ClientId = builder.Configuration["Microsoft:ClientId"];
        options.ClientSecret = builder.Configuration["Microsoft:ClientSecret"];
    });
}

if (builder.Configuration["GitHub:ClientId"] != null && builder.Configuration["GitHub:ClientSecret"] != null)
{
    authBuilder.AddTwitter(options =>
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ConsumerKey = builder.Configuration["GitHub:ClientId"];
        options.ConsumerSecret = builder.Configuration["GitHub:ClientSecret"];
    });
}

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseAuthorization();

app.MapControllers();

app.Run();
