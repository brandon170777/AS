using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;

namespace WebApplication1.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext db;

        public LogoutModel(SignInManager<ApplicationUser> signInManager,
                           UserManager<ApplicationUser> userManager,
                           AuthDbContext db)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.db = db;
        }

        public IActionResult OnGet()
        {
            return RedirectToPage("Index");
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await userManager.GetUserAsync(User);

            if (user != null)
            {
                // 🔐 Clear active session ID so another device can log in
                user.ActiveSessionId = null;
                await userManager.UpdateAsync(user);

                db.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "Logout",
                    IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    Device = Request.Headers["User-Agent"]
                });
                await db.SaveChangesAsync();
            }

            // Clear session
            HttpContext.Session.Clear();

            // Sign out Identity
            await signInManager.SignOutAsync();

            return RedirectToPage("Login");
        }
    }
}
