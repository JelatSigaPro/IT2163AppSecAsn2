using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using BookwormOnline.Model;
using BookwormOnline.Services;
using Microsoft.AspNetCore.WebUtilities;

namespace BookwormOnline.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<ForgotPasswordModel> _logger;
        private readonly IEmailSender _emailSender;
        private readonly AuthDbContext _db;

        public ForgotPasswordModel(UserManager<ApplicationUser> userManager, ILogger<ForgotPasswordModel> logger, IEmailSender emailSender, AuthDbContext db)
        {
            _userManager = userManager;
            _logger = logger;
            _emailSender = emailSender;
            _db = db;
        }

        [BindProperty]
        public ForgotPasswordViewModel FModel { get; set; } = new();

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(FModel.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Email Not found");
                _logger.LogWarning("Password reset requested for non-existing email.");
                return Page();
            }

            // Generate Reset Token & Encode it properly
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token)); // Encode correctly

            var resetLink = Url.Page("/ResetPassword", null, new { email = FModel.Email, token = encodedToken }, Request.Scheme);

            await _emailSender.SendEmailAsync(
                FModel.Email,
                "Reset Your Password",
                $"Click <a href='{resetLink}'>here</a> to reset your password."
            );

            // Log the password reset request
            _db.AuditLogs.Add(new AuditLog
            {
                UserEmail = user.Email,
                Action = "Password Reset Requested",
                Timestamp = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();

            _logger.LogInformation("Password reset email sent.");
            return RedirectToPage("/Login"); // Redirect properly
        }
    }

    public class ForgotPasswordViewModel
    {
        [Required]
        [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    ErrorMessage = "Invalid email format. Example: user@example.com")]
        public string Email { get; set; }
    }
}
