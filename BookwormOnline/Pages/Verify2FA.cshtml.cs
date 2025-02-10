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
        private readonly ILogger<Verify2FAModel> _logger;
        private readonly IEmailSender _emailSender; // If using Email

        public Verify2FAModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<Verify2FAModel> logger, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
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
                    _logger.LogWarning("Invalid 2FA code entered by user {Email}.", user.Email);
                    return Page();
                }

                _logger.LogInformation("User {Email} successfully authenticated with 2FA.", user.Email);
                return RedirectToPage("/Index");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error verifying 2FA for user {Email}", VModel?.Code);
                ModelState.AddModelError("", "An error occurred while verifying your authentication code. Please try again.");
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
                    _logger.LogError("Failed to generate 2FA token for user {Email}.", user.Email);
                    ModelState.AddModelError("", "An error occurred while generating the authentication code. Please try again.");
                    return Page();
                }

                // Send the token via Email
                await _emailSender.SendEmailAsync(user.Email, "Your Two-Factor Authentication Code", $"Your 2FA code is: {token}");
                _logger.LogInformation("2FA token sent to user {Email}.", user.Email);

                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending 2FA code to user {Email}.", VModel?.Code);
                ModelState.AddModelError("", "An error occurred while sending your authentication code. Please try again.");
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
