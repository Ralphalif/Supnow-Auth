FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["src/Supnow-Auth/Supnow-Auth.csproj", "src/Supnow-Auth/"]
RUN dotnet restore "src/Supnow-Auth/Supnow-Auth.csproj"
COPY . .
WORKDIR "/src/src/Supnow-Auth"
RUN dotnet build "Supnow-Auth.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Supnow-Auth.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Supnow-Auth.dll"] 