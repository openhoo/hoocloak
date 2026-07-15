FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:ed034a8bf0b24ded0cbbac07e17825d8e9ebfe21e308191d0f7421eaf5ad4664 AS build
WORKDIR /src

COPY Hoocloak.AspNetApi.csproj packages.lock.json ./
RUN dotnet restore Hoocloak.AspNetApi.csproj --locked-mode

COPY . ./
RUN dotnet publish Hoocloak.AspNetApi.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:1fa23fc4872d95fd71c2833ebe65d7e84a43b2d51a31d119516852f13d9505a7 AS final
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=5099
EXPOSE 5099
COPY --from=build /app/publish ./
USER $APP_UID
ENTRYPOINT ["dotnet", "Hoocloak.AspNetApi.dll"]
