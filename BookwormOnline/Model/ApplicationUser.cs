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

        public string SessionToken { get; set; } // Unique session identifier
    }
}
