using Microsoft.AspNetCore.Identity;
using Pgrsms.Models;

namespace Pgrsms.Data
{
    public static class IdentitySeed
    {
        public static async Task SeedRolesAndAdminAsync(
            RoleManager<IdentityRole> roleManager,
            UserManager<ApplicationUser> userManager)
        {
            string[] roles = new[] { "Student", "Consultant", "Admin" };
            foreach (var r in roles)
                if (!await roleManager.RoleExistsAsync(r))
                    await roleManager.CreateAsync(new IdentityRole(r));

            var adminEmail = "admin@pgrsms.local";
            var admin = await userManager.FindByEmailAsync(adminEmail);
            if (admin == null)
            {
                admin = new ApplicationUser { UserName = adminEmail, Email = adminEmail, EmailConfirmed = true };
                var result = await userManager.CreateAsync(admin, "Admin#12345");
                if (result.Succeeded) await userManager.AddToRoleAsync(admin, "Admin");
            }
        }
    }
}
