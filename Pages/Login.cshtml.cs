using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.ViewModels;

namespace WebApplication1.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext db;

        // 🔐 Maximum password age: 2 minutes
        private const int MaxPasswordAgeMinutes = 2;

        [BindProperty]
        public LoginViewModel LModel { get; set; }

        public LoginModel(SignInManager<ApplicationUser> signInManager,
                          UserManager<ApplicationUser> userManager,
                          AuthDbContext db)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.db = db;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            var user = await userManager.FindByEmailAsync(LModel.Email);

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return Page();
            }

            var result = await signInManager.PasswordSignInAsync(
                user.UserName,
                LModel.Password,
                false,
                lockoutOnFailure: true
            );

            if (result.Succeeded)
            {
                // 🔐 Maximum password age check (2 minutes)
                var passwordAge = DateTime.UtcNow - user.PasswordLastChanged;
                if (passwordAge.TotalMinutes > MaxPasswordAgeMinutes)
                {
                    var sessionId = Guid.NewGuid().ToString();
                    user.ActiveSessionId = sessionId;
                    await userManager.UpdateAsync(user);

                    HttpContext.Session.SetString("UserId", user.Id);
                    HttpContext.Session.SetString("SessionId", sessionId);

                    TempData["PasswordExpired"] = "Your password has expired (older than 2 minutes). Please change it now.";
                    return RedirectToPage("ChangePassword");
                }

                // ✅ Always replace any previous session
                var newSessionId = Guid.NewGuid().ToString();
                user.ActiveSessionId = newSessionId;
                await userManager.UpdateAsync(user);

                HttpContext.Session.SetString("UserId", user.Id);
                HttpContext.Session.SetString("SessionId", newSessionId);

                db.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "Login",
                    IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    Device = Request.Headers["User-Agent"]
                });
                await db.SaveChangesAsync();

                return RedirectToPage("Index");
            }

            if (result.RequiresTwoFactor)
            {
                // ✅ Reserve session for 2FA flow
                var pendingSessionId = Guid.NewGuid().ToString();
                user.ActiveSessionId = pendingSessionId;
                await userManager.UpdateAsync(user);

                HttpContext.Session.SetString("UserId", user.Id);
                HttpContext.Session.SetString("SessionId", pendingSessionId);

                return RedirectToPage("LoginWith2fa");
            }

            if (result.IsLockedOut)
            {
                db.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "AccountLocked",
                    IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    Device = Request.Headers["User-Agent"]
                });
                await db.SaveChangesAsync();

                ModelState.AddModelError("", "Account locked after 3 failed attempts. Try again later.");
                return Page();
            }

            db.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Action = "FailedLogin",
                IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                Device = Request.Headers["User-Agent"]
            });
            await db.SaveChangesAsync();

            ModelState.AddModelError("", "Invalid login attempt.");
            return Page();
        }
    }
}
