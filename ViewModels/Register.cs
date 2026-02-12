using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

public class Register
{
    [Required(ErrorMessage = "First name is required")]
    [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
    [RegularExpression(@"^[a-zA-Z\s\-']+$", ErrorMessage = "First name must not contain special characters")]
    public string FirstName { get; set; }

    [Required(ErrorMessage = "Last name is required")]
    [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
    [RegularExpression(@"^[a-zA-Z\s\-']+$", ErrorMessage = "Last name must not contain special characters")]
    public string LastName { get; set; }

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; }

    // 🔐 Strong password (meets assignment requirement)
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    [MinLength(12, ErrorMessage = "Password must be at least 12 characters")]
    [RegularExpression(
        @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$",
        ErrorMessage = "Password must contain uppercase, lowercase, number and special character"
    )]
    public string Password { get; set; }

    [Required(ErrorMessage = "Confirm password is required")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; }

    [Required(ErrorMessage = "Mobile number is required")]
    [RegularExpression(@"^\d{8}$", ErrorMessage = "Mobile number must be exactly 8 digits")]
    public string MobileNo { get; set; }

    [Required(ErrorMessage = "Billing address is required")]
    public string BillingAddress { get; set; }

    [Required(ErrorMessage = "Shipping address is required")]
    [RegularExpression(@"^[a-zA-Z0-9\s,.\-#/]+$", ErrorMessage = "Shipping address must not contain special characters")]
    public string ShippingAddress { get; set; }

    [Required(ErrorMessage = "Credit card number is required")]
    [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit card must be exactly 16 digits")]
    public string CreditCard { get; set; }


    [Required(ErrorMessage = "Profile photo is required")]
    public IFormFile Photo { get; set; }
}
