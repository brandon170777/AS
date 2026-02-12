using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace WebApplication1.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly AuthDbContext db;

        [BindProperty]
        public ChangePassword CPModel { get; set; }

        // Minimum password age: cannot change within 2 minutes of last change
        private const int MinPasswordAgeMinutes = 2;

        public ChangePasswordModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            AuthDbContext db)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.db = db;
        }

        public IActionResult OnGet()
        {
            if (HttpContext.Session.GetString("UserId") == null)
                return RedirectToPage("Login");

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            var userId = HttpContext.Session.GetString("UserId");
            var user = await userManager.FindByIdAsync(userId);

            if (user == null)
            {
                HttpContext.Session.Clear();
                return RedirectToPage("Login");
            }

            // 🔐 Minimum password age check
            var timeSinceLastChange = DateTime.UtcNow - user.PasswordLastChanged;
            if (timeSinceLastChange.TotalMinutes < MinPasswordAgeMinutes)
            {
                var remaining = MinPasswordAgeMinutes - (int)timeSinceLastChange.TotalMinutes;
                ModelState.AddModelError("",
                    $"You cannot change your password yet. Please wait {remaining} more minute(s).");
                return Page();
            }

            // 🔐 Check current password — cannot reuse the one you're already using
            var currentCheck = userManager.PasswordHasher.VerifyHashedPassword(
                user, user.PasswordHash!, CPModel.NewPassword);
            if (currentCheck == PasswordVerificationResult.Success)
            {
                ModelState.AddModelError("", "You cannot reuse your current password.");
                return Page();
            }

            // 🔐 Check last 2 password history (reuse prevention)
            var lastPasswords = await db.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.ChangedOn)
                .Take(2)
                .ToListAsync();

            foreach (var old in lastPasswords)
            {
                if (userManager.PasswordHasher.VerifyHashedPassword(
                        user,
                        old.PasswordHash,
                        CPModel.NewPassword) == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("", "You cannot reuse your last 2 passwords.");
                    return Page();
                }
            }

            // 🔐 Change password
            var result = await userManager.ChangePasswordAsync(
                user,
                CPModel.OldPassword,
                CPModel.NewPassword
            );

            if (result.Succeeded)
            {
                // 🔐 Update password last changed timestamp         
                user.PasswordLastChanged = DateTime.UtcNow;

                // 🔐 Clear active session so user can log in again
                user.ActiveSessionId = null;
                await userManager.UpdateAsync(user);

                // 🔐 Save new password hash into history
                db.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = user.PasswordHash!
                });

                await db.SaveChangesAsync();

                // 🔐 Clear session and sign out — user must re-login with new password
                HttpContext.Session.Clear();
                await signInManager.SignOutAsync();

                return RedirectToPage("Login");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return Page();
        }
    }
}
