using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.ViewModels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Net.Mail;

namespace WebApplication1.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly IConfiguration configuration;
        private readonly AuthDbContext db;
        private readonly IDataProtectionProvider dataProtectionProvider;

        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration,
            AuthDbContext db,
            IDataProtectionProvider dataProtectionProvider)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.configuration = configuration;
            this.db = db;
            this.dataProtectionProvider = dataProtectionProvider;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            /* =========================
               1️⃣ Google reCAPTCHA v3
            ========================= */
            var token = Request.Form["recaptchaToken"];
            if (string.IsNullOrEmpty(token))
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed.");
                return Page();
            }

            var secret = configuration["GoogleReCaptcha:SecretKey"];

            using var client = new HttpClient();
            var response = await client.PostAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret={secret}&response={token}",
                null);

            var jsonResponse = await response.Content.ReadAsStringAsync();
            var captchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);

            if (captchaResult == null || !captchaResult.success)
            {
                ModelState.AddModelError(string.Empty, "Bot verification failed.");
                return Page();
            }

            // reCAPTCHA v3 scores on localhost are often low; use 0.3 threshold
            if (captchaResult.score < 0.3)
            {
                ModelState.AddModelError(string.Empty, $"Bot verification failed (score: {captchaResult.score}).");
                return Page();
            }

            if (!string.IsNullOrEmpty(captchaResult.action) && captchaResult.action != "register")
            {
                ModelState.AddModelError(string.Empty, "Bot verification failed.");
                return Page();
            }

            /* =========================
               2️⃣ Email uniqueness
            ========================= */
            var existingUser = await userManager.FindByEmailAsync(RModel.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("RModel.Email", "Email is already registered.");
                return Page();
            }

            /* =========================
               3️⃣ Secure photo validation
            ========================= */
            if (RModel.Photo == null)
            {
                ModelState.AddModelError("RModel.Photo", "Profile photo is required.");
                return Page();
            }

            if (!RModel.Photo.ContentType.Equals("image/jpeg", StringComparison.OrdinalIgnoreCase))
            {
                ModelState.AddModelError("RModel.Photo", "Only JPG images are allowed.");
                return Page();
            }

            if (RModel.Photo.Length > 2 * 1024 * 1024)
            {
                ModelState.AddModelError("RModel.Photo", "File size must not exceed 2MB.");
                return Page();
            }

            var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");
            Directory.CreateDirectory(uploadsFolder);

            var fileName = $"{Guid.NewGuid()}.jpg";
            var filePath = Path.Combine(uploadsFolder, fileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await RModel.Photo.CopyToAsync(stream);
            }

            /* =========================
               4️⃣ Data Protection (encrypt credit card only)
            ========================= */
            var protector = dataProtectionProvider.CreateProtector("CreditCardProtector");

            var encoder = HtmlEncoder.Default;

            var user = new ApplicationUser
            {
                UserName = RModel.Email,
                Email = RModel.Email,

                FirstName = encoder.Encode(RModel.FirstName),
                LastName = encoder.Encode(RModel.LastName),

                // Plain text fields (HTML-encoded for XSS prevention)
                MobileNo = RModel.MobileNo,
                BillingAddress = encoder.Encode(RModel.BillingAddress),
                ShippingAddress = encoder.Encode(RModel.ShippingAddress),

                // 🔐 Encrypted field
                EncryptedCreditCard = protector.Protect(RModel.CreditCard),

                PhotoPath = "/uploads/" + fileName,
                PasswordLastChanged = DateTime.UtcNow
            };

            var result = await userManager.CreateAsync(user, RModel.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                return Page();
            }

            /* =========================
               5️⃣ Password history
            ========================= */
            db.PasswordHistories.Add(new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash!
            });

            await db.SaveChangesAsync();

            /* =========================
               6️⃣ Send email confirmation link
            ========================= */
            var emailToken = await userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(emailToken));

            var confirmLink = Url.Page(
                "/ConfirmEmail",
                null,
                new { userId = user.Id, token = encodedToken },
                Request.Scheme);

            var smtp = configuration["Email:Smtp"];
            var sender = configuration["Email:Sender"];
            var emailPassword = configuration["Email:Password"];
            var port = int.Parse(configuration["Email:Port"]!);

            var smtpClient = new SmtpClient(smtp, port)
            {
                Credentials = new System.Net.NetworkCredential(sender, emailPassword),
                EnableSsl = true
            };

            var mail = new MailMessage
            {
                From = new MailAddress(sender!),
                Subject = "Bookworms Online \u2013 Confirm Your Email",
                Body = $"Please confirm your email by clicking the link below:\n\n{confirmLink}"
            };

            mail.To.Add(user.Email!);
            smtpClient.Send(mail);

            TempData["EmailConfirmation"] = "Registration successful! Please check your email to confirm your account before logging in.";
            return RedirectToPage("Login");
        }
    }

    public class RecaptchaResponse
    {
        public bool success { get; set; }
        public float score { get; set; }
        public string action { get; set; }
    }
}
