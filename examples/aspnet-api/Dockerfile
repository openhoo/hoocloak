FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Hoocloak.AspNetApi.csproj packages.lock.json ./
RUN dotnet restore Hoocloak.AspNetApi.csproj --locked-mode

COPY . ./
RUN dotnet publish Hoocloak.AspNetApi.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=5099
EXPOSE 5099
COPY --from=build /app/publish ./
USER $APP_UID
ENTRYPOINT ["dotnet", "Hoocloak.AspNetApi.dll"]
