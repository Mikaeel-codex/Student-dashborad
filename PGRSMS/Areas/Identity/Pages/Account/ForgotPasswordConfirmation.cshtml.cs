using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;


namespace Pgrsms.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ForgotPasswordConfirmationModel : PageModel
    {
        public string? DevResetLink { get; set; }
        public void OnGet(string? resetLink = null)
        {
            DevResetLink = resetLink; // shown only in development scenario
        }
    }
}