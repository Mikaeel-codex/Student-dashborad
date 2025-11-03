# ---------- Build stage ----------
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy solution if present and project file, then restore
COPY *.sln ./
COPY PGRSMS/*.csproj PGRSMS/
RUN dotnet restore

# Copy the rest and publish
COPY . .
RUN dotnet publish PGRSMS/PGRSMS.csproj -c Release -o /app

# ---------- Runtime stage ----------
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app ./

ENV ASPNETCORE_URLS=http://0.0.0.0:${PORT}
ENV ASPNETCORE_ENVIRONMENT=Production

CMD ["dotnet", "PGRSMS.dll"]
