using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddictBare.Models;

namespace OpenIddictBare
{
    public class OpenIddictHostedService : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IConfiguration _config;

        public OpenIddictHostedService(IServiceProvider serviceProvider, IConfiguration config)
        {
            _serviceProvider = serviceProvider;
            _config = config;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            var idpClients = _config.GetSection("Clients").Get<IEnumerable<IdpClient>>();
            if (idpClients == null || !idpClients.Any())
            {
                throw new Exception("No clients have been configured!");
            }

            using var scope = _serviceProvider.CreateScope();

            var context = scope.ServiceProvider.GetRequiredService<DbContext>();
            await context.Database.EnsureCreatedAsync(cancellationToken);

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var scopePermissions = _config.GetSection("Scopes").Get<string[]>().Select(x =>
                        OpenIddictConstants.Permissions.Prefixes.Scope + x).ToList();

            foreach (var idpClient in idpClients)
            {
                var app = new OpenIddictApplicationDescriptor
                {
                    ClientId = idpClient.ClientId,
                    ClientSecret = idpClient.ClientSecret,
                    DisplayName = idpClient.Name,
                    
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Authorization,
                        OpenIddictConstants.Permissions.Endpoints.Token,

                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                        OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                        OpenIddictConstants.Permissions.ResponseTypes.Code

                        
                    }
                };

                if (idpClient.IsPublic)
                {
                    app.Type = OpenIddictConstants.ClientTypes.Public;
                    app.ClientSecret = null;
                } else
                {
                    app.Type = OpenIddictConstants.ClientTypes.Confidential;
                }
                
                foreach (var perm in scopePermissions)
                {
                    app.Permissions.Add(perm);
                }

                if (idpClient.RedirectUrls != null)
                {
                    foreach (var uri in idpClient.RedirectUrls)
                    {
                        app.RedirectUris.Add(new Uri(uri));
                    }
                }

                await manager.CreateAsync(app, cancellationToken);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
