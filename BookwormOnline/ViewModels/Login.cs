using System.ComponentModel.DataAnnotations;

namespace BookwormOnline.ViewModels
{
    public class LoginViewModel
    {
        [Required]
        [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    ErrorMessage = "Invalid email format. Example: user@example.com")]
        public string Email { get; set; }

        [Required]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])[A-Za-z\d$@$!%*?&]{12,}$",
        ErrorMessage = "Password must be at least 12 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.")]
        public string Password { get; set; }
    }
}
