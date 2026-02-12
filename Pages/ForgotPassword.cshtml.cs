using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using System.Net.Mail;
using System.Security.Cryptography;

namespace WebApplication1.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly IConfiguration configuration;
        private readonly AuthDbContext db;

        [BindProperty]
        public string Email { get; set; }

        public ForgotPasswordModel(
            UserManager<ApplicationUser> userManager,
            IConfiguration configuration,
            AuthDbContext db)
        {
            this.userManager = userManager;
            this.configuration = configuration;
            this.db = db;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            var user = await userManager.FindByEmailAsync(Email);

            // Do not reveal if user exists
            if (user == null)
            {
                ViewData["Message"] = "If the account exists, an OTP has been sent.";
                return Page();
            }

            // ===============================
            // EMAIL OTP CODE
            // ===============================
            var otpCode = RandomNumberGenerator.GetInt32(0, 1000000).ToString("D6");

            db.OtpCodes.Add(new OtpCode
            {
                UserId = user.Id,
                Code = otpCode,
                Expiry = DateTime.UtcNow.AddMinutes(10),
                Used = false
            });

            await db.SaveChangesAsync();

            var smtp = configuration["Email:Smtp"];
            var sender = configuration["Email:Sender"];
            var password = configuration["Email:Password"];
            var port = int.Parse(configuration["Email:Port"]!);

            using var client = new SmtpClient(smtp, port)
            {
                Credentials = new System.Net.NetworkCredential(sender, password),
                EnableSsl = true,
                Timeout = 10000
            };

            var mail = new MailMessage
            {
                From = new MailAddress(sender!),
                Subject = "Bookworms Online – OTP Password Reset",
                Body = $"Your OTP code is: {otpCode}\n\nThis code expires in 10 minutes."
            };

            mail.To.Add(user.Email!);
            await client.SendMailAsync(mail);

            TempData["UserId"] = user.Id;
            return RedirectToPage("VerifyOtp");
        }
    }
}
