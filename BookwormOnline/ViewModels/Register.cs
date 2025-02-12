using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using Microsoft.AspNetCore.Http;

public class Register
{
    [Required]
    [StringLength(100)]
    [RegularExpression(@"^[A-Za-z\s]+$", ErrorMessage = "First name must contain only letters.")]
    public string FirstName { get; set; }

    [Required]
    [StringLength(100)]
    [RegularExpression(@"^[A-Za-z\s]+$", ErrorMessage = "Last name must contain only letters.")]
    public string LastName { get; set; }

    [Required]
    [DataType(DataType.CreditCard)]
    [StringLength(16, MinimumLength = 16, ErrorMessage = "Credit Card Number must be exactly 16 digits.")]
    public string CreditCardNo { get; set; } // Will be encrypted before storing

    [Required]
    [RegularExpression(@"^\d{8}$", ErrorMessage = "Mobile number must be exactly 8 digits.")]
    public string MobileNo { get; set; }

    [Required]
    public string BillingAddress { get; set; }

    [Required]
    public string ShippingAddress { get; set; } // Allows all special characters

    [Required]
    [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    ErrorMessage = "Invalid email format. Example: user@example.com")]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])[A-Za-z\d$@$!%*?&]{12,}$",
        ErrorMessage = "Password must be at least 12 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.")]
    public string Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; }

    [Required]
    [DataType(DataType.Upload)]
    [AllowedFileExtensions(new string[] { ".jpg" }, ErrorMessage = "Only .JPG files are allowed.")]
    public IFormFile Photo { get; set; } // Restrict to .JPG only
}

public class AllowedFileExtensionsAttribute : ValidationAttribute
{
    private readonly string[] _extensions;

    public AllowedFileExtensionsAttribute(string[] extensions)
    {
        _extensions = extensions;
    }

    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        var file = value as IFormFile;
        if (file != null)
        {
            var extension = Path.GetExtension(file.FileName).ToLower();
            if (!_extensions.Contains(extension))
            {
                return new ValidationResult($"Only {string.Join(", ", _extensions)} files are allowed.");
            }
        }
        return ValidationResult.Success;
    }
}