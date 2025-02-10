using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BookwormOnline.Model;
using BookwormOnline.ViewModels;

namespace BookwormOnline.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<ChangePasswordModel> _logger;

        // Define Minimum Password Age Policy
        private readonly TimeSpan MinPasswordAge = TimeSpan.FromDays(1);

        public ChangePasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<ChangePasswordModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]
        public ChangePasswordViewModel PModel { get; set; } = new();

        public async Task<IActionResult> OnGetAsync(bool forceChange = false)
        {
            if (forceChange)
            {
                ModelState.AddModelError("", "Your password has expired. Please change it before continuing.");
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    _logger.LogWarning("Change password form validation failed.");
                    return Page();
                }

                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    _logger.LogWarning("User not found when trying to change password.");
                    return RedirectToPage("/Login");
                }

                // Enforce Minimum Password Age
                if (user.LastPasswordChangeDate.HasValue)
                {
                    var timeSinceLastChange = DateTime.UtcNow - user.LastPasswordChangeDate.Value;
                    if (timeSinceLastChange < MinPasswordAge)
                    {
                        ModelState.AddModelError("", $"You can only change your password once every {MinPasswordAge.Days} day(s). Please try again later.");
                        _logger.LogWarning("User {Email} attempted to change password too soon.", user.Email);
                        return Page();
                    }
                }

                // Check if Old Password Matches the Stored Hashed Password
                string enteredOldPasswordHash = HashPasswordWithSalt(PModel.OldPassword, user.PasswordSalt);
                if (enteredOldPasswordHash != user.PasswordHash)
                {
                    ModelState.AddModelError("", "The current password is incorrect.");
                    _logger.LogWarning("Password change failed: Incorrect old password for user {Email}", user.Email);
                    return Page();
                }

                // Generate a New Salt & Hash the New Password
                string newSalt;
                string newHashedPassword;
                GenerateSaltAndHash(PModel.NewPassword, out newHashedPassword, out newSalt);

                // Check if the new password matches any of the last 2 passwords
                if (newHashedPassword == user.PasswordHash ||
                    newHashedPassword == user.PreviousPasswordHash1 ||
                    newHashedPassword == user.PreviousPasswordHash2)
                {
                    ModelState.AddModelError("", "You cannot reuse your last two passwords. Please choose a different password.");
                    _logger.LogWarning("Password change failed: User {Email} attempted to reuse an old password.", user.Email);
                    return Page();
                }

                // Update Password and Shift Password History
                user.PreviousPasswordHash2 = user.PreviousPasswordHash1;
                user.PreviousPasswordHash1 = user.PasswordHash;
                user.PasswordHash = newHashedPassword;
                user.PasswordSalt = newSalt;  // Store new salt
                user.LastPasswordChangeDate = DateTime.UtcNow;

                var updateResult = await _userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    _logger.LogError("Password update failed for user {Email}.", user.Email);
                    foreach (var error in updateResult.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return Page();
                }

                // Force User to Log In Again After Changing Password
                await _signInManager.SignOutAsync();
                _logger.LogInformation("User {Email} changed password successfully.", user.Email);

                return RedirectToPage("/Login", new { message = "Password changed successfully. Please log in again." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error while changing password for user {Email}", PModel?.OldPassword);
                return RedirectToPage("/Errors/500");
            }
        }

        // Helper Function: Generate New Salt & Hash Password
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

        // Helper Function: Hash Password with an Existing Salt
        private string HashPasswordWithSalt(string password, string salt)
        {
            try
            {
                using (SHA512Managed hashing = new SHA512Managed())
                {
                    string passwordWithSalt = password + salt;
                    byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(passwordWithSalt));
                    return Convert.ToBase64String(hashWithSalt);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error hashing password with salt.");
                return "HashError";
            }
        }
    }
}
