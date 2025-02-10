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
        private readonly ILogger<ResetPasswordModel> _logger;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<ResetPasswordModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]
        public ResetPasswordViewModel RModel { get; set; } = new();

        public void OnGet(string token, string email)
        {
            RModel.Email = email;
            RModel.Token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token)); // ? Decode properly
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
                    _logger.LogWarning("Password reset failed: User not found for email {Email}", RModel.Email);
                    return RedirectToPage("/Login");
                }

                // Generate a New Salt & Hash the New Password
                string newSalt;
                string newHashedPassword;
                GenerateSaltAndHash(RModel.NewPassword, out newHashedPassword, out newSalt);

                // Check if the new password was used before
                if (newHashedPassword == user.PasswordHash ||
                    newHashedPassword == user.PreviousPasswordHash1 ||
                    newHashedPassword == user.PreviousPasswordHash2)
                {
                    ModelState.AddModelError("", "You cannot reuse your last two passwords. Please choose a different password.");
                    _logger.LogWarning("Password reset failed: User {Email} attempted to reuse an old password.", user.Email);
                    return Page();
                }

                // Shift password history (keep last 2 passwords)
                user.PreviousPasswordHash2 = user.PreviousPasswordHash1;
                user.PreviousPasswordHash1 = user.PasswordHash;
                user.PasswordHash = newHashedPassword;
                user.PasswordSalt = newSalt;  // Store new salt
                user.LastPasswordChangeDate = DateTime.UtcNow; // Update last password change

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


                //Force logout after password reset
                await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();
                _logger.LogInformation("User {Email} successfully reset password.", user.Email);
                return RedirectToPage("/Login", new { message = "Password has been reset successfully. Please log in." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error while resetting password for user {Email}", RModel.Email);
                return RedirectToPage("/Error/500");
            }
        }

        //Helper Function: Generate New Salt & Hash Password
        private void GenerateSaltAndHash(string password, out string finalHash, out string salt)
        {
            try
            {
                // Generate a random salt
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                byte[] saltByte = new byte[8]; // 8-byte salt
                rng.GetBytes(saltByte);
                salt = Convert.ToBase64String(saltByte);

                // Hash password + salt
                SHA512Managed hashing = new SHA512Managed();
                string pwdWithSalt = password + salt;
                byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                finalHash = Convert.ToBase64String(hashWithSalt);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating salt and hashing password.");
                finalHash = "HashError";
                salt = "SaltError";
            }
        }
    }
}
