<<<<<<< HEAD
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Pgrsms.Data;
using Pgrsms.Models;
using System.IO;

var builder = WebApplication.CreateBuilder(args);

// ---------- DB ----------
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ---------- Identity + Roles ----------
builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.Password.RequiredLength = 8;
        options.Password.RequireDigit = true;
        options.Password.RequireNonAlphanumeric = true;
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedEmail = false;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders()
    .AddDefaultUI();

// Persistent auth cookie (stores login for future use)
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Account/Login";
    options.LogoutPath = "/Identity/Account/Logout";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.ExpireTimeSpan = TimeSpan.FromDays(30);
    options.SlidingExpiration = true;
});

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();


// ---------- Persist DataProtection keys (prevents cookie breakage across runs) ----------
var keysPath = Path.Combine(AppContext.BaseDirectory, "keys");
Directory.CreateDirectory(keysPath);

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysPath))
    .SetApplicationName("Pgrsms");

// Antiforgery cookie setup (new name so old cookies are ignored on fresh runs)
builder.Services.AddAntiforgery(o =>
{
    o.Cookie.Name = "Pgrsms.AntiForgery";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Lax;
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// Show text for error status codes (helps see what's happening)
app.UseStatusCodePages("text/plain", "Status code: {0}");

// ---------- Pre-Identity cookie scrub (fixes 400s on first GET to Login/Register) ----------
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Method == "GET" &&
        ctx.Request.Path.StartsWithSegments("/Identity", StringComparison.OrdinalIgnoreCase))
    {
        // If we see any old antiforgery/auth cookies, delete and retry once
        var bad = ctx.Request.Cookies.Keys
            .Where(k =>
                k.StartsWith(".AspNetCore.Antiforgery", StringComparison.OrdinalIgnoreCase) ||
                k.Equals("Pgrsms.AntiForgery", StringComparison.OrdinalIgnoreCase) ||
                k.Equals(".AspNetCore.Identity.Application", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (bad.Count > 0)
        {
            foreach (var k in bad) ctx.Response.Cookies.Delete(k);
            ctx.Response.Redirect(ctx.Request.Path + ctx.Request.QueryString);
            return;
        }
    }

    await next();
});

// ---------- Antiforgery rescue (if a token decryption error still sneaks through) ----------
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (AntiforgeryValidationException)
    {
        context.Response.Cookies.Delete("Pgrsms.AntiForgery");
        foreach (var k in context.Request.Cookies.Keys.Where(k => k.StartsWith(".AspNetCore.Antiforgery")))
            context.Response.Cookies.Delete(k);
        context.Response.Redirect(context.Request.Path + context.Request.QueryString);
    }
});

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// Simple health ping
app.MapGet("/healthz", () => Results.Ok(new { ok = true }));

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

// ---------- Auto-migrate + seed roles/admin ----------
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var db = services.GetRequiredService<ApplicationDbContext>();
    await db.Database.MigrateAsync();

    var roleMgr = services.GetRequiredService<RoleManager<IdentityRole>>();
    var userMgr = services.GetRequiredService<UserManager<ApplicationUser>>();
    await IdentitySeed.SeedRolesAndAdminAsync(roleMgr, userMgr);
}

app.Run();
=======
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Pgrsms.Data;
using Pgrsms.Models;
using System.IO;

var builder = WebApplication.CreateBuilder(args);

// ---------------- DB ----------------
var sqlServerCs = builder.Configuration.GetConnectionString("DefaultConnection");
var sqliteCs = builder.Configuration.GetConnectionString("SqliteConnection");

// Use SQLite in Production (Render), SQL Server locally
if (builder.Environment.IsProduction())
{
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlite(sqliteCs));
}
else
{
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(sqlServerCs));
}

// ---------------- Identity + Roles ----------------
builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.Password.RequiredLength = 8;
        options.Password.RequireDigit = true;
        options.Password.RequireNonAlphanumeric = true;
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedEmail = false;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders()
    .AddDefaultUI();

// Persistent auth cookie
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Account/Login";
    options.LogoutPath = "/Identity/Account/Logout";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.ExpireTimeSpan = TimeSpan.FromDays(30);
    options.SlidingExpiration = true;
});

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

// ---------- Persist DataProtection keys (container-safe) ----------
var keysPath = Path.Combine(AppContext.BaseDirectory, "keys");
Directory.CreateDirectory(keysPath);

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysPath))
    .SetApplicationName("Pgrsms");

// Antiforgery cookie setup
builder.Services.AddAntiforgery(o =>
{
    o.Cookie.Name = "Pgrsms.AntiForgery";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Lax;
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// Helpful status text
app.UseStatusCodePages("text/plain", "Status code: {0}");

// ---------- Pre-Identity cookie scrub ----------
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Method == "GET" &&
        ctx.Request.Path.StartsWithSegments("/Identity", StringComparison.OrdinalIgnoreCase))
    {
        var bad = ctx.Request.Cookies.Keys
            .Where(k =>
                k.StartsWith(".AspNetCore.Antiforgery", StringComparison.OrdinalIgnoreCase) ||
                k.Equals("Pgrsms.AntiForgery", StringComparison.OrdinalIgnoreCase) ||
                k.Equals(".AspNetCore.Identity.Application", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (bad.Count > 0)
        {
            foreach (var k in bad) ctx.Response.Cookies.Delete(k);
            ctx.Response.Redirect(ctx.Request.Path + ctx.Request.QueryString);
            return;
        }
    }

    await next();
});

// ---------- Antiforgery rescue ----------
app.Use(async (context, next) =>
{
    try { await next(); }
    catch (AntiforgeryValidationException)
    {
        context.Response.Cookies.Delete("Pgrsms.AntiForgery");
        foreach (var k in context.Request.Cookies.Keys.Where(k => k.StartsWith(".AspNetCore.Antiforgery")))
            context.Response.Cookies.Delete(k);
        context.Response.Redirect(context.Request.Path + context.Request.QueryString);
    }
});

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// Simple health check
app.MapGet("/healthz", () => Results.Ok(new { ok = true }));

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

// ---------- DB init ----------
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var db = services.GetRequiredService<ApplicationDbContext>();

    if (app.Environment.IsProduction())
    {
        // With SQLite, migrations created for SQL Server can be incompatible.
        // For a quick deploy, ensure schema exists:
        db.Database.EnsureCreated();
        // If you later add SQLite migrations, switch to: db.Database.Migrate();
    }
    else
    {
        // Local dev (SQL Server): apply migrations
        await db.Database.MigrateAsync();
    }

    var roleMgr = services.GetRequiredService<RoleManager<IdentityRole>>();
    var userMgr = services.GetRequiredService<UserManager<ApplicationUser>>();
    await IdentitySeed.SeedRolesAndAdminAsync(roleMgr, userMgr);
}

app.Run();
>>>>>>> 0c1dfe8 (added SQLlit)
