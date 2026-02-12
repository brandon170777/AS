using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using System.Net.Mail;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace WebApplication1.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly IConfiguration configuration;

        [BindProperty]
        public string Email { get; set; }

        public ForgotPasswordModel(
            UserManager<ApplicationUser> userManager,
            IConfiguration configuration)
        {
            this.userManager = userManager;
            this.configuration = configuration;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            var user = await userManager.FindByEmailAsync(Email);

            // Do not reveal if user exists
            if (user == null)
            {
                ViewData["Message"] = "If the account exists, a reset link has been sent.";
                return Page();
            }

            // ===============================
            // EMAIL RESET LINK
            // ===============================
            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            var resetLink = Url.Page(
                "/ResetPassword",
                null,
                new { userId = user.Id, token = encodedToken },
                Request.Scheme);

            var smtp = configuration["Email:Smtp"];
            var sender = configuration["Email:Sender"];
            var password = configuration["Email:Password"];
            var port = int.Parse(configuration["Email:Port"]!);

            var client = new SmtpClient(smtp, port)
            {
                Credentials = new System.Net.NetworkCredential(sender, password),
                EnableSsl = true
            };

            var mail = new MailMessage
            {
                From = new MailAddress(sender!),
                Subject = "Bookworms Online – Password Reset",
                Body = $"Click the link below to reset your password:\n\n{resetLink}"
            };

            mail.To.Add(user.Email!);
            client.Send(mail);

            ViewData["Message"] = "Password reset link sent to your email.";
            return Page();
        }
    }
}
