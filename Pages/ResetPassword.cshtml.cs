using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.ViewModels;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace WebApplication1.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext db;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, AuthDbContext db)
        {
            this.userManager = userManager;
            this.db = db;
        }

        [BindProperty]
        public string UserId { get; set; }

        [BindProperty]
        public string Token { get; set; }

        [BindProperty]
        [Required]
        [DataType(DataType.Password)]
        [MinLength(12, ErrorMessage = "Password must be at least 12 characters")]
        [RegularExpression(
            @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$",
            ErrorMessage = "Password must contain uppercase, lowercase, number and special character")]
        public string NewPassword { get; set; }

        [BindProperty]
        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(NewPassword), ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; }

        // ✅ IMPORTANT: capture token/userId from query string
        public IActionResult OnGet(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
                return RedirectToPage("Login");

            UserId = userId;
            Token = token;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await userManager.FindByIdAsync(UserId);
            if (user == null) return RedirectToPage("Login");

            // 🔐 Check current password — cannot reuse the one you're already using
            var currentCheck = userManager.PasswordHasher.VerifyHashedPassword(
                user, user.PasswordHash!, NewPassword);
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
                        NewPassword) == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("", "You cannot reuse your last 2 passwords.");
                    return Page();
                }
            }

            // ✅ Decode token back to original format
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(Token));

            var result = await userManager.ResetPasswordAsync(user, decodedToken, NewPassword);

            if (result.Succeeded)
            {
                // ✅ Unlock account after reset
                await userManager.SetLockoutEndDateAsync(user, null);
                await userManager.ResetAccessFailedCountAsync(user);

                // 🔐 Reset the password age timer
                user.PasswordLastChanged = DateTime.UtcNow;
                await userManager.UpdateAsync(user);

                // 🔐 Save to password history
                db.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = user.PasswordHash!
                });
                await db.SaveChangesAsync();

                return RedirectToPage("Login");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Description);

            return Page();
        }
    }
}
