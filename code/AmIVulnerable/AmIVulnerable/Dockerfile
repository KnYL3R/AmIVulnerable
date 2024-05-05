FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

# Modells
WORKDIR /src/Modells
COPY Modells/Modells.csproj .
RUN dotnet restore Modells.csproj

# API
WORKDIR /src/AmIVulnerable
COPY AmIVulnerable/AmIVulnerable.csproj .
RUN dotnet restore AmIVulnerable.csproj

# API build
RUN dotnet dev-certs https --trust
WORKDIR /src
COPY . .
RUN dotnet build AmIVulnerable/AmIVulnerable.csproj -c Release -o /app/build

FROM build AS publish
RUN dotnet publish AmIVulnerable/AmIVulnerable.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY AmIVulnerable/Controllers/Views /app/Controllers/Views
COPY --from=publish /root/.dotnet/corefx/cryptography/x509stores/my/* /root/.dotnet/corefx/cryptography/x509stores/my/
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AmIVulnerable.dll"]

# Install NodeJS and git
RUN apt-get update
RUN apt-get install -y curl gnupg
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
RUN apt-get install -y nodejs git

EXPOSE 80
EXPOSE 443
