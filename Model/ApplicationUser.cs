using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Model
{
    public class ApplicationUser : IdentityUser
    {
        [Required, StringLength(50)]
        public string FirstName { get; set; }

        [Required, StringLength(50)]
        public string LastName { get; set; }

        // Store ENCRYPTED credit card only
        [Required]
        public string EncryptedCreditCard { get; set; }

        [Required, Phone]
        public string MobileNo { get; set; }

        [Required, StringLength(200)]
        public string BillingAddress { get; set; }

        // Allow special characters: don't over-restrict; validate length only
        [Required, StringLength(200)]
        public string ShippingAddress { get; set; }

        // Save jpg file path / filename
        public string PhotoPath { get; set; }

        // 🔐 Track when the password was last changed (min/max password age)
        public DateTime PasswordLastChanged { get; set; } = DateTime.UtcNow;

        // 🔐 Track active session to prevent multiple device login
        public string? ActiveSessionId { get; set; }
    }
}
