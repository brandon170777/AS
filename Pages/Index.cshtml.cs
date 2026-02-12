using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.DataProtection;
using WebApplication1.Model;

namespace WebApplication1.Pages
{
    public class IndexModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _db;

        public IndexModel(
            UserManager<ApplicationUser> userManager,
            IDataProtectionProvider dataProtectionProvider,
            SignInManager<ApplicationUser> signInManager,
            AuthDbContext db)
        {
            _userManager = userManager;
            _dataProtectionProvider = dataProtectionProvider;
            _signInManager = signInManager;
            _db = db;
        }

        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Mobile { get; set; }
        public string Billing { get; set; }
        public string Shipping { get; set; }
        public string CreditCard { get; set; }
        public string PhotoPath { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // 🔐 Enforce session
            var userId = HttpContext.Session.GetString("UserId");
            var sessionId = HttpContext.Session.GetString("SessionId");

            if (userId == null || sessionId == null)
            {
                return RedirectToPage("/Login");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                HttpContext.Session.Clear();
                return RedirectToPage("/Login");
            }

            // 🔐 Validate this session is still the active one
            if (user.ActiveSessionId != sessionId)
            {
                HttpContext.Session.Clear();
                await _signInManager.SignOutAsync();
                TempData["SessionKicked"] = "Another login was detected. You have been logged out.";
                return RedirectToPage("/Login");
            }

            // 🔐 Decrypt credit card
            var protector = _dataProtectionProvider.CreateProtector("CreditCardProtector");

            FirstName = user.FirstName;
            LastName = user.LastName;
            Email = user.Email!;
            Mobile = user.MobileNo;
            Billing = user.BillingAddress;
            Shipping = user.ShippingAddress;
            PhotoPath = user.PhotoPath;

            try
            {
                CreditCard = protector.Unprotect(user.EncryptedCreditCard);
            }
            catch
            {
                CreditCard = "[Unable to decrypt]";
            }

            return Page();
        }
    }
}

