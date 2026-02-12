using System.ComponentModel.DataAnnotations;

namespace WebApplication1.ViewModels
{
    public class ForgotPassword
    {
        [Required]
        [EmailAddress]
        public required string Email { get; set; }

        [Required]
        public required string Method { get; set; }
    }
}
