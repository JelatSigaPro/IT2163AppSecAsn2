using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;
using BookwormOnline.Model;
using Microsoft.AspNetCore.Authorization;

namespace BookwormOnline.Pages
{
    [Authorize(Roles = "Admin,User")]
    public class Enable2FAModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _db;
        private readonly ILogger<Enable2FAModel> _logger;

        public Enable2FAModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, AuthDbContext db, ILogger<Enable2FAModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _db = db;
            _logger = logger;
        }

        public async Task<IActionResult> OnGet()
        {
            try
            {
                // Check if any users exist
                bool usersExist = _userManager.Users.Any();
                if (!usersExist)
                {
                    _logger.LogWarning("No users found. Redirecting to Register page.");
                    return RedirectToPage("/Register");
                }

                // Check if the user exists
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    _logger.LogWarning("User session invalid. Redirecting to Login page.");
                    return RedirectToPage("/Login");
                }

                // Check if the password was last updated more than 90 days ago
                if (user.LastPasswordChangeDate.HasValue)
                {
                    var passwordAge = DateTime.UtcNow - user.LastPasswordChangeDate.Value;
                    if (passwordAge > TimeSpan.FromDays(90))
                    {
                        _logger.LogWarning("User must change password due to max age policy.");
                        return RedirectToPage("/ChangePassword", new { forceChange = true });
                    }
                }

                // Check if the session token is the same
                string storedToken = HttpContext.Session.GetString("SessionToken");
                if (string.IsNullOrEmpty(storedToken) || user.SessionToken != storedToken)
                {
                    _logger.LogWarning("Session token mismatch for user. Logging out.");
                    await _signInManager.SignOutAsync();
                    HttpContext.Session.Clear();
                    return RedirectToPage("/Login");
                }

                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error occurred on Enable2FA page.");
                return RedirectToPage("/Errors/500");
            }
        }

        public async Task<IActionResult> OnPostEnable2FAAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            user.Is2FAEnabled = true;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User enabled 2FA.");

            // Log enabling 2FA
            _db.AuditLogs.Add(new AuditLog
            {
                UserEmail = user.Email,
                Action = "Enabled 2FA",
                Timestamp = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();

            return RedirectToPage("/Index");
        }

        public async Task<IActionResult> OnPostDisable2FAAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            user.Is2FAEnabled = false;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User disabled 2FA.");

            // Log disabling 2FA
            _db.AuditLogs.Add(new AuditLog
            {
                UserEmail = user.Email,
                Action = "Disabled 2FA",
                Timestamp = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();

            return RedirectToPage("/Index");
        }
    }
}
