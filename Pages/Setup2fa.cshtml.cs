using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;

namespace WebApplication1.Pages
{
    public class Setup2faModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;

        public Setup2faModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        public string SharedKey { get; set; }
        public string QrCodeUri { get; set; }
        public bool Is2faEnabled { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Verification code is required")]
        [StringLength(7, MinimumLength = 6, ErrorMessage = "Code must be 6 digits")]
        public string VerificationCode { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (userId == null) return RedirectToPage("Login");

            var user = await userManager.FindByIdAsync(userId);
            if (user == null) return RedirectToPage("Login");

            Is2faEnabled = await userManager.GetTwoFactorEnabledAsync(user);

            if (!Is2faEnabled)
            {
                await LoadSharedKeyAndQrCodeAsync(user);
            }

            return Page();
        }

        // Enable 2FA
        public async Task<IActionResult> OnPostEnableAsync()
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (userId == null) return RedirectToPage("Login");

            var user = await userManager.FindByIdAsync(userId);
            if (user == null) return RedirectToPage("Login");

            if (!ModelState.IsValid)
            {
                await LoadSharedKeyAndQrCodeAsync(user);
                Is2faEnabled = false;
                return Page();
            }

            var code = VerificationCode.Replace(" ", "").Replace("-", "");

            var isValid = await userManager.VerifyTwoFactorTokenAsync(
                user,
                userManager.Options.Tokens.AuthenticatorTokenProvider,
                code);

            if (!isValid)
            {
                ModelState.AddModelError("VerificationCode",
                    "Invalid verification code. Scan the QR code again and try.");
                await LoadSharedKeyAndQrCodeAsync(user);
                Is2faEnabled = false;
                return Page();
            }

            // Enable 2FA
            await userManager.SetTwoFactorEnabledAsync(user, true);
            Is2faEnabled = true;

            TempData["StatusMessage"] = "2FA has been enabled. You will now need your authenticator app to log in.";
            return RedirectToPage("Setup2fa");
        }

        // Disable 2FA
        public async Task<IActionResult> OnPostDisableAsync()
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (userId == null) return RedirectToPage("Login");

            var user = await userManager.FindByIdAsync(userId);
            if (user == null) return RedirectToPage("Login");

            await userManager.SetTwoFactorEnabledAsync(user, false);
            await userManager.ResetAuthenticatorKeyAsync(user);

            // Re-sign in to refresh the security stamp
            await signInManager.RefreshSignInAsync(user);

            TempData["StatusMessage"] = "2FA has been disabled.";
            return RedirectToPage("Setup2fa");
        }

        private async Task LoadSharedKeyAndQrCodeAsync(ApplicationUser user)
        {
            // Reset key if user doesn't have one yet
            var key = await userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await userManager.ResetAuthenticatorKeyAsync(user);
                key = await userManager.GetAuthenticatorKeyAsync(user);
            }

            SharedKey = FormatKey(key!);
            QrCodeUri = GenerateQrCodeUri(user.Email!, key!);
        }

        private static string FormatKey(string unformattedKey)
        {
            var result = new StringBuilder();
            int currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
                currentPosition += 4;
            }
            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.AsSpan(currentPosition));
            }
            return result.ToString().ToLowerInvariant();
        }

        private static string GenerateQrCodeUri(string email, string key)
        {
            return $"otpauth://totp/BookwormsOnline:{UrlEncoder.Default.Encode(email)}" +
                   $"?secret={key}&issuer=BookwormsOnline&digits=6";
        }
    }
}