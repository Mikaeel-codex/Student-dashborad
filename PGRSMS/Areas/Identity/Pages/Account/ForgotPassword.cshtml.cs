using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Pgrsms.Models;


namespace Pgrsms.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;


        public ForgotPasswordModel(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }


        [BindProperty]
        public InputModel Input { get; set; } = new();


        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;
        }


        public void OnGet() { }


        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();


            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null /*|| !(await _userManager.IsEmailConfirmedAsync(user))*/)
            {
                // Do not reveal that the user does not exist or is not confirmed
                return RedirectToPage("./ForgotPasswordConfirmation");
            }


            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = Url.Page("/Account/ResetPassword", pageHandler: null,
            values: new { area = "Identity", code, email = Input.Email }, protocol: Request.Scheme)!;


            // For development: show the link on the confirmation page
            return RedirectToPage("./ForgotPasswordConfirmation", new { resetLink = callbackUrl });
        }
    }
}