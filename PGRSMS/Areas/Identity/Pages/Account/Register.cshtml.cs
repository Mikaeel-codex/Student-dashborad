using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Pgrsms.Models;

namespace Pgrsms.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    [IgnoreAntiforgeryToken] // <— disable antiforgery (dev fix)
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [BindProperty] public InputModel Input { get; set; } = new();
        public string? ReturnUrl { get; set; }

        public class InputModel
        {
            [Required, EmailAddress] public string Email { get; set; } = string.Empty;

            [Required, StringLength(100, MinimumLength = 8)]
            [DataType(DataType.Password)]
            public string Password { get; set; } = string.Empty;

            [DataType(DataType.Password)]
            [Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; } = string.Empty;
        }

        public void OnGet(string? returnUrl = null)
        {
            ReturnUrl = string.IsNullOrEmpty(returnUrl) || !Url.IsLocalUrl(returnUrl)
                ? Url.Content("~/")
                : returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            ReturnUrl = string.IsNullOrEmpty(returnUrl) || !Url.IsLocalUrl(returnUrl)
                ? Url.Content("~/")
                : returnUrl;

            if (!ModelState.IsValid) return Page();

            var user = new ApplicationUser { UserName = Input.Email, Email = Input.Email, EmailConfirmed = true };
            var result = await _userManager.CreateAsync(user, Input.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Student");
                await _signInManager.SignInAsync(user, isPersistent: true);
                return LocalRedirect("~/Student");
            }

            foreach (var err in result.Errors)
                ModelState.AddModelError(string.Empty, err.Description);

            return Page();
        }
    }
}
