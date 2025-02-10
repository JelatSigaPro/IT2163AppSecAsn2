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
using Microsoft.AspNetCore.Authorization;

namespace BookwormOnline.Pages
{
    [Authorize(Roles = "Admin,User")]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _db;
        private readonly ILogger<ChangePasswordModel> _logger;

        // Define Minimum Password Age Policy
        private readonly TimeSpan MinPasswordAge = TimeSpan.FromDays(1);

        public ChangePasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, AuthDbContext db, ILogger<ChangePasswordModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _db = db;
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

                //Enforce Minimum Password Age
                if (user.LastPasswordChangeDate.HasValue)
                {
                    var timeSinceLastChange = DateTime.UtcNow - user.LastPasswordChangeDate.Value;
                    if (timeSinceLastChange < MinPasswordAge)
                    {
                        ModelState.AddModelError("", $"You can only change your password once every {MinPasswordAge.Days} day(s). Please try again later.");
                        _logger.LogWarning("User attempted to change password too soon.");
                        return Page();
                    }
                }

                //Check if Old Password Matches the Stored Hashed Password
                string enteredOldPasswordHash = HashPasswordWithSalt(PModel.OldPassword, user.PasswordSalt);
                if (enteredOldPasswordHash != user.PasswordHash)
                {
                    ModelState.AddModelError("", "The current password is incorrect.");
                    _logger.LogWarning("Password change failed: Incorrect old password for user.");

                    // Log failed password change attempt
                    _db.AuditLogs.Add(new AuditLog
                    {
                        UserEmail = user.Email,
                        Action = "Failed Password Change Attempt",
                        Timestamp = DateTime.UtcNow
                    });
                    await _db.SaveChangesAsync();

                    return Page();
                }

                //Hash New Password Using Existing Salt (Do NOT Generate New Salt)
                string existingSalt = user.PasswordSalt;
                string newHashedPassword = HashPasswordWithSalt(PModel.NewPassword, existingSalt);

                // Check if the new password matches any of the last 2 passwords
                if (newHashedPassword == user.PasswordHash ||
                    newHashedPassword == user.PreviousPasswordHash1 ||
                    newHashedPassword == user.PreviousPasswordHash2)
                {
                    ModelState.AddModelError("", "You cannot reuse your last two passwords. Please choose a different password.");
                    _logger.LogWarning("Password change failed: User attempted to reuse an old password.");

                    // Log failed password change attempt
                    _db.AuditLogs.Add(new AuditLog
                    {
                        UserEmail = user.Email,
                        Action = "Failed Password Change Attempt",
                        Timestamp = DateTime.UtcNow
                    });
                    await _db.SaveChangesAsync();

                    return Page();
                }

                // Update Password and Shift Password History
                user.PreviousPasswordHash2 = user.PreviousPasswordHash1;
                user.PreviousPasswordHash1 = user.PasswordHash;
                user.PasswordHash = newHashedPassword;
                user.LastPasswordChangeDate = DateTime.UtcNow;

                var updateResult = await _userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    _logger.LogError("Password update failed for user.");
                    foreach (var error in updateResult.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return Page();
                }

                // Log successful password change
                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = user.Email,
                    Action = "Password Changed",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                // Force User to Log In Again After Changing Password
                await _signInManager.SignOutAsync();
                _logger.LogInformation("User changed password successfully.");

                return RedirectToPage("/Login", new { message = "Password changed successfully. Please log in again." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error while changing password for user.");

                // Log unexpected error
                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = User.Identity?.Name,
                    Action = "Password Change Error",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                return RedirectToPage("/Errors/500");
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

