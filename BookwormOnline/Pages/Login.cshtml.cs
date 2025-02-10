using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BookwormOnline.Model;
using BookwormOnline.ViewModels;
using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace BookwormOnline.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly ILogger<LoginModel> _logger;

        [BindProperty]
        public LoginViewModel LModel { get; set; }

        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext db, ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
            _logger = logger;
        }

        public void OnGet(string? message = null)
        {
            if (!string.IsNullOrEmpty(message))
            {
                ViewData["SuccessMessage"] = message;
            }
        }

        [ValidateAntiForgeryToken] // Enforce CSRF protection
        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return Page();
                }

                // Validate reCAPTCHA token
                string recaptchaToken = Request.Form["g-recaptcha-response"];
                if (string.IsNullOrEmpty(recaptchaToken) || !await ValidateRecaptcha(recaptchaToken))
                {
                    _logger.LogWarning("reCAPTCHA validation failed.");
                    ModelState.AddModelError("", "reCAPTCHA failed. Please try again.");
                    return Page();
                }

                var user = await _userManager.FindByEmailAsync(LModel.Email);
                _logger.LogInformation("Login attempt for user");

                if (user == null)
                {
                    _logger.LogWarning("Login failed: User not found");
                    ModelState.AddModelError("", "Invalid credentials.");
                    return Page();
                }

                if (await _userManager.IsLockedOutAsync(user))
                {
                    _logger.LogWarning("Locked out user attempted login.");
                    ModelState.AddModelError("", "Too many failed login attempts. Your account is locked for 5 minutes.");
                    return Page();
                }

                string enteredPasswordHash = HashPasswordWithSalt(LModel.Password, user.PasswordSalt);
                if (enteredPasswordHash != user.PasswordHash)
                {
                    await _userManager.AccessFailedAsync(user);
                    int attemptsLeft = 3 - await _userManager.GetAccessFailedCountAsync(user);

                    if (attemptsLeft <= 0)
                    {
                        await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(5));
                        _logger.LogWarning("User is locked out due to multiple failed attempts.");
                        ModelState.AddModelError("", "Too many failed login attempts. Your account is locked for 5 minutes.");

                        // Log account lockout
                        _db.AuditLogs.Add(new AuditLog
                        {
                            UserEmail = user.Email,
                            Action = "Account Locked",
                            Timestamp = DateTime.UtcNow
                        });
                        await _db.SaveChangesAsync();
                    }
                    else
                    {
                        _logger.LogWarning("Invalid credentials.");
                        ModelState.AddModelError("", $"Invalid credentials. {attemptsLeft} attempt(s) left.");

                        // Log failed login attempt
                        _db.AuditLogs.Add(new AuditLog
                        {
                            UserEmail = user.Email,
                            Action = "Failed Login Attempt",
                            Timestamp = DateTime.UtcNow
                        });
                        await _db.SaveChangesAsync();
                    }
                    return Page();
                }

                await _userManager.ResetAccessFailedCountAsync(user);

                // Log successful login
                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = user.Email,
                    Action = "Login",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                string newSessionToken = GenerateSessionToken();
                if (!string.IsNullOrEmpty(user.SessionToken))
                {
                    await _userManager.UpdateSecurityStampAsync(user);
                }

                user.SessionToken = newSessionToken;
                await _userManager.UpdateAsync(user);
                HttpContext.Session.SetString("SessionToken", newSessionToken);

                await _signInManager.SignInAsync(user, isPersistent: false);
                _logger.LogInformation("User logged in successfully.");

                if (user.LastPasswordChangeDate.HasValue)
                {
                    var passwordAge = DateTime.UtcNow - user.LastPasswordChangeDate.Value;
                    if (passwordAge > TimeSpan.FromDays(90))
                    {
                        _logger.LogWarning("User must change password due to max age policy.");
                        return RedirectToPage("/ChangePassword", new { forceChange = true }); // Redirect to Change Password
                    }
                }

                if (user.Is2FAEnabled)
                {
                    return RedirectToPage("/Verify2FA");
                }

                return RedirectToPage("Index");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during login.");

                // Log unexpected error
                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = LModel.Email,
                    Action = "Login Error",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                return RedirectToPage("/Error/500");
            }
        }


        private async Task<bool> ValidateRecaptcha(string token)
        {
            using (var httpClient = new HttpClient())
            {
                var response = await httpClient.PostAsync($"https://www.google.com/recaptcha/api/siteverify?secret=&response={token}", null);
                var jsonResponse = await response.Content.ReadAsStringAsync();

                Console.WriteLine("reCAPTCHA Response: " + jsonResponse); // Debugging
                var recaptchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);

                if (!recaptchaResult.success)
                {
                    Console.WriteLine("?? reCAPTCHA validation failed!");
                }
                else
                {
                    Console.WriteLine("? reCAPTCHA validation succeeded with score: " + recaptchaResult.score);
                }

                return recaptchaResult.success && recaptchaResult.score >= 0.5;
            }
        }

        // Model for parsing JSON response
        private class RecaptchaResponse
        {
            public bool success { get; set; }
            public float score { get; set; }
            public string action { get; set; }
            public string challenge_ts { get; set; }
            public string hostname { get; set; }
        }



        private string HashPasswordWithSalt(string password, string salt)
        {
            try
            {
                using (SHA512Managed hashing = new SHA512Managed())
                {
                    string pwdWithSalt = password + salt;
                    byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                    return Convert.ToBase64String(hashWithSalt);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error hashing password with salt.");
                return "HashError";
            }
        }

        private string GenerateSessionToken()
        {
            try
            {
                using (var rng = RandomNumberGenerator.Create())
                {
                    byte[] tokenBytes = new byte[32];
                    rng.GetBytes(tokenBytes);
                    return Convert.ToBase64String(tokenBytes);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate session token.");
                return "SessionError";
            }
        }
    }
}
