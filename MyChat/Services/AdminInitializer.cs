using Microsoft.AspNetCore.Identity;
using MyChat.Models;

namespace MyChat.Services;

public class AdminInitializer
{
    public static async Task SeedRolesAndAdmin(RoleManager<IdentityRole<int>> _roleManager, UserManager<User> _userManager)
    {
        string adminEmail = "admin@admin.admin";
        string adminUserName = "AdminAdminovich";
        string adminPassword = "Admin123$QwE";
        string adminAvatar = "https://lastfm.freetls.fastly.net/i/u/ar0/3d4d85e22cd52ef84204fcc92c394f11.jpg";
        DateTime adminDateOfBirth = new DateTime(2002, 2, 22).ToUniversalTime();
        
        var roles = new [] { "admin", "user" };
        
        foreach (var role in roles)
        {
            if (await _roleManager.FindByNameAsync(role) == null)
                await _roleManager.CreateAsync(new IdentityRole<int>(role));
        }
        if (await _userManager.FindByNameAsync(adminEmail) == null)
        {
            User admin = new User { Email = adminEmail, UserName = adminUserName, Avatar = adminAvatar, DateOfBirth = adminDateOfBirth };
            IdentityResult result = await _userManager.CreateAsync(admin, adminPassword);
            if (result.Succeeded)
                await _userManager.AddToRoleAsync(admin, "admin");
        }
    }
}