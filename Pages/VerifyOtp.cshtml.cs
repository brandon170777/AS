using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Model;
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Pages
{
    public class VerifyOtpModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext db;

        [BindProperty]
        [Required(ErrorMessage = "OTP is required")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "OTP must be 6 digits")]
        public string OtpCode { get; set; }

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

        public VerifyOtpModel(UserManager<ApplicationUser> userManager, AuthDbContext db)
        {
            this.userManager = userManager;
            this.db = db;
        }

        public IActionResult OnGet()
        {
            if (TempData["UserId"] == null)
                return RedirectToPage("Login");

            // Keep UserId across the form post
            TempData.Keep("UserId");
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                TempData.Keep("UserId");
                return Page();
            }

            var userId = TempData["UserId"]?.ToString();
            if (string.IsNullOrEmpty(userId))
            {
                ModelState.AddModelError("", "Session expired. Please request a new OTP.");
                return Page();
            }

            // Find the latest unused OTP for this user
            var otp = await db.OtpCodes
                .Where(o => o.UserId == userId && o.Code == OtpCode && !o.Used)
                .OrderByDescending(o => o.Expiry)
                .FirstOrDefaultAsync();

            if (otp == null || otp.Expiry < DateTime.Now)
            {
                ModelState.AddModelError("", "Invalid or expired OTP.");
                TempData["UserId"] = userId; // preserve for retry
                return Page();
            }

            // Mark OTP as used
            otp.Used = true;

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
                return RedirectToPage("Login");

            // Generate a password reset token and reset
            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var result = await userManager.ResetPasswordAsync(user, token, NewPassword);

            if (result.Succeeded)
            {
                // Unlock account
                await userManager.SetLockoutEndDateAsync(user, null);
                await userManager.ResetAccessFailedCountAsync(user);

                // Update password history
                user.PasswordLastChanged = DateTime.UtcNow;
                await userManager.UpdateAsync(user);

                db.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = user.PasswordHash
                });
                await db.SaveChangesAsync();

                TempData["Message"] = "Password reset successfully. Please login.";
                return RedirectToPage("Login");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Description);

            TempData["UserId"] = userId;
            return Page();
        }
    }
}