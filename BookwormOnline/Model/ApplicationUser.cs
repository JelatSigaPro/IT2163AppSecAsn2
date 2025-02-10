using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace BookwormOnline.Model
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        [Required]
        public string CreditCardNo { get; set; } // Encrypted

        [Required]
        public string MobileNo { get; set; }

        [Required]
        public string BillingAddress { get; set; }

        [Required]
        public string ShippingAddress { get; set; }

        public string PhotoPath { get; set; }
        [Required]
        public string PasswordHash { get; set; }

        [Required]
        public string PasswordSalt { get; set; }

        public string PreviousPasswordHash1 { get; set; }

        public string PreviousPasswordHash2 { get; set; }
        public DateTime? LastPasswordChangeDate { get; set; } // ✅ Tracks last password change
        public string SessionToken { get; set; } // Unique session identifier
        public bool Is2FAEnabled { get; set; } = false;  // Indicates if the user has 2FA enabled
    }
}
