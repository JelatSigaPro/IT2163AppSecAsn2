using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using BookwormOnline.Model;
using BookwormOnline.Services;

namespace BookwormOnline.Pages
{
    public class Verify2FAModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _db;
        private readonly ILogger<Verify2FAModel> _logger;
        private readonly IEmailSender _emailSender; // If using Email

        public Verify2FAModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, AuthDbContext db, ILogger<Verify2FAModel> logger, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _db = db;
            _logger = logger;
            _emailSender = emailSender; // Service to send 2FA code
        }

        [BindProperty]
        public Verify2FAViewModel VModel { get; set; } = new();

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    _logger.LogWarning("User session invalid. Redirecting to Login.");
                    return RedirectToPage("/Login");
                }

                // Verify the Two-Factor Authentication Token
                var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, VModel.Code);
                if (!isValid)
                {
                    ModelState.AddModelError("", "Invalid authentication code. Please try again.");
                    _logger.LogWarning("Invalid 2FA code entered by user.");

                    // Log failed 2FA attempt
                    _db.AuditLogs.Add(new AuditLog
                    {
                        UserEmail = user.Email,
                        Action = "Failed 2FA Attempt",
                        Timestamp = DateTime.UtcNow
                    });
                    await _db.SaveChangesAsync();

                    return Page();
                }

                _logger.LogInformation("User successfully authenticated with 2FA.");

                // Log successful 2FA
                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = user.Email,
                    Action = "Successful 2FA",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                return RedirectToPage("/Index");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error verifying 2FA for user");
                ModelState.AddModelError("", "An error occurred while verifying your authentication code. Please try again.");

                // Log unexpected error
                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = User.Identity?.Name,
                    Action = "2FA Verification Error",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                return Page();
            }
        }

        public async Task<IActionResult> OnGetAsync()
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    _logger.LogWarning("User session invalid. Redirecting to Login.");
                    return RedirectToPage("/Login");
                }

                // Generate a 2FA Token
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

                if (string.IsNullOrEmpty(token))
                {
                    _logger.LogError("Failed to generate 2FA token for user.");
                    ModelState.AddModelError("", "An error occurred while generating the authentication code. Please try again.");
                    return Page();
                }

                // Send the token via Email
                await _emailSender.SendEmailAsync(user.Email, "Your Two-Factor Authentication Code", $"Your 2FA code is: {token}");
                _logger.LogInformation("2FA token sent to user.");

                // Log 2FA token sent
                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = user.Email,
                    Action = "2FA Token Sent",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending 2FA code to user.");
                ModelState.AddModelError("", "An error occurred while sending your authentication code. Please try again.");

                // Log unexpected error
                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = User.Identity?.Name,
                    Action = "2FA Token Send Error",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                return Page();
            }
        }
    }

    public class Verify2FAViewModel
    {
        [Required]
        [Display(Name = "Authentication Code")]
        public string Code { get; set; }
    }
}


