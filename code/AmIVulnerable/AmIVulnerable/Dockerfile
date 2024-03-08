FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

# Modells
WORKDIR /src/Modells
COPY Modells/Modells.csproj .
RUN dotnet restore Modells.csproj

# LiteDbLib
WORKDIR /src/LiteDbLib
COPY LiteDbLib/LiteDbLib.csproj .
RUN dotnet restore LiteDbLib.csproj

# API
WORKDIR /src/AmIVulnerable
COPY AmIVulnerable/AmIVulnerable.csproj .
RUN dotnet restore AmIVulnerable.csproj

# API build
WORKDIR /src
COPY . .
RUN dotnet build AmIVulnerable/AmIVulnerable.csproj -c Release -o /app/build

FROM build AS publish
RUN dotnet publish AmIVulnerable/AmIVulnerable.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM node:latest AS nodeANDgit
# npm and git installation
RUN apt-get update && apt-get install -y git && apt-get install -y nodejs npm

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY AmIVulnerable/Controllers/Views /app/Controllers/Views
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AmIVulnerable.dll"]

EXPOSE 80
EXPOSE 443
