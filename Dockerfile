FROM mcr.microsoft.com/dotnet/sdk:6.0 AS builder
WORKDIR /app
COPY ./OpenIddictBare/OpenIddictBare.csproj ./OpenIddictBare/OpenIddictBare.csproj
COPY ./OpenIddictBare.sln ./OpenIddictBare.sln
RUN dotnet restore
COPY . .
RUN dotnet build --no-restore -c Release ./OpenIddictBare
RUN dotnet publish -c Release --no-build -o out ./OpenIddictBare

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS runner
COPY --from=builder /app/out /app
WORKDIR /app
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
ENV ASPNETCORE_SYSTEM_GLOBALIZATION_INVARIANT=1
ENV ASPNETCORE_URLS=http://*:80
ENV ASPNETCORE_ENVIRONMENT=Production
EXPOSE 80
CMD ["dotnet", "OpenIddictBare.dll"]