using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Pages
{
    public class LoginWith2faModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext db;

        // 🔐 Maximum password age: 2 minutes (must match Login.cshtml.cs)
        private const int MaxPasswordAgeMinutes = 2;

        [BindProperty]
        [Required(ErrorMessage = "Authenticator code is required")]
        [StringLength(7, MinimumLength = 6, ErrorMessage = "Code must be 6 digits")]
        public string TwoFactorCode { get; set; }

        public LoginWith2faModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AuthDbContext db)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.db = db;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return RedirectToPage("/Login");

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return RedirectToPage("/Login");

            var sessionId = HttpContext.Session.GetString("SessionId");
            if (string.IsNullOrEmpty(sessionId) || user.ActiveSessionId != sessionId)
            {
                TempData["LoginBlocked"] = "This account already has a previous login in another browser/device.";
                return RedirectToPage("/Login");
            }

            // Strip spaces/hyphens from the code
            var code = TwoFactorCode.Replace(" ", "").Replace("-", "");

            var result = await signInManager.TwoFactorAuthenticatorSignInAsync(
                code, false, false);

            if (result.Succeeded)
            {
                var passwordAge = DateTime.UtcNow - user.PasswordLastChanged;
                if (passwordAge.TotalMinutes > MaxPasswordAgeMinutes)
                {
                    TempData["PasswordExpired"] = "Your password has expired (older than 2 minutes). Please change it now.";
                    return RedirectToPage("ChangePassword");
                }

                HttpContext.Session.SetString("UserId", user.Id);

                db.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "Login (2FA)",
                    IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    Device = Request.Headers["User-Agent"]
                });
                await db.SaveChangesAsync();

                return RedirectToPage("Index");
            }

            if (result.IsLockedOut)
            {
                db.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "AccountLocked (2FA)",
                    IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    Device = Request.Headers["User-Agent"]
                });
                await db.SaveChangesAsync();

                ModelState.AddModelError("", "Account locked. Try again later.");
                return Page();
            }

            ModelState.AddModelError("", "Invalid authenticator code.");
            return Page();
        }
    }
}