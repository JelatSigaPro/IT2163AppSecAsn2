using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Text;
using System.Threading.Tasks;
using BookwormOnline.Model;
using BookwormOnline.ViewModels;
using System.Security.Cryptography;

namespace BookwormOnline.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _db;
        private readonly ILogger<ResetPasswordModel> _logger;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, AuthDbContext db, ILogger<ResetPasswordModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _db = db;
            _logger = logger;
        }

        [BindProperty]
        public ResetPasswordViewModel RModel { get; set; } = new();

        public void OnGet(string token, string email)
        {
            RModel.Email = email;
            RModel.Token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token)); // Decode properly
        }

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    _logger.LogWarning("Reset password form validation failed.");
                    return Page();
                }

                var user = await _userManager.FindByEmailAsync(RModel.Email);
                if (user == null)
                {
                    _logger.LogWarning("Password reset failed: User not found for email.");
                    return RedirectToPage("/Login");
                }

                // Generate a New Salt & Hash the New Password
                // Use the existing salt instead of generating a new one
                string existingSalt = user.PasswordSalt;
                string newHashedPassword = HashPasswordWithSalt(RModel.NewPassword, existingSalt);

                // Ensure new password is not in password history
                if (newHashedPassword == user.PasswordHash ||
                    newHashedPassword == user.PreviousPasswordHash1 ||
                    newHashedPassword == user.PreviousPasswordHash2)
                {
                    ModelState.AddModelError("", "You cannot reuse your last two passwords. Please choose a different password.");
                    _logger.LogWarning("Password reset failed: User {Email} attempted to reuse an old password.", user.Email);

                    // Log failed password reset attempt
                    _db.AuditLogs.Add(new AuditLog
                    {
                        UserEmail = user.Email,
                        Action = "Failed Password Reset Attempt",
                        Timestamp = DateTime.UtcNow
                    });
                    await _db.SaveChangesAsync();

                    return Page();
                }

                // Shift password history (keep last 2 passwords)
                user.PreviousPasswordHash2 = user.PreviousPasswordHash1;
                user.PreviousPasswordHash1 = user.PasswordHash;
                user.PasswordHash = newHashedPassword;
                user.LastPasswordChangeDate = DateTime.UtcNow; // Update last password change date

                var updateResult = await _userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    _logger.LogError("Password reset failed for user {Email}.", user.Email);
                    foreach (var error in updateResult.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return Page();
                }

                // Log successful password reset
                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = user.Email,
                    Action = "Password Reset",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                // Force logout after password reset
                await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();
                _logger.LogInformation("User successfully reset password.");
                return RedirectToPage("/Login", new { message = "Password has been reset successfully. Please log in." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error while resetting password for user.");

                // Log unexpected error
                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = RModel.Email,
                    Action = "Password Reset Error",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                return RedirectToPage("/Error/500");
            }
        }

        // Helper Function: Hash Password with an Existing Salt
        private string HashPasswordWithSalt(string password, string salt)
        {
            try
            {
                using (SHA512Managed hashing = new SHA512Managed())
                {
                    string pwdWithSalt = password + salt; // Combine password with existing salt
                    byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                    return Convert.ToBase64String(hashWithSalt);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error hashing password with existing salt.");
                return "HashError";
            }
        }
    }
}

