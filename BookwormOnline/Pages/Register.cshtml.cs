using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BookwormOnline.Model;
using System.Net;
using System.Data.SqlTypes;

namespace BookwormOnline.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<RegisterModel> _logger;

        [BindProperty]
        public Register RModel { get; set; }

        private readonly byte[] encryptionKey;
        private readonly byte[] iv;

        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration, ILogger<RegisterModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _logger = logger;

            encryptionKey = Convert.FromBase64String(_configuration["EncryptionSettings:AESKey"]);
            iv = Convert.FromBase64String(_configuration["EncryptionSettings:AESIV"]);
        }

        public void OnGet()
        {
            try
            {
                if (!_userManager.Users.Any())
                {
                    ViewData["ShowAdminRegisterMessage"] = "No users found. Please register an admin account.";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while checking existing users.");
                RedirectToPage("/Error/500");
            }
        }

        private string EncodeInput(string input)
        {
            return WebUtility.HtmlEncode(input);
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

                var existingUser = await _userManager.FindByEmailAsync(RModel.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError("RModel.Email", "Email is already taken.");
                    return Page();
                }

                string photoPath = null;
                if (RModel.Photo != null)
                {
                    try
                    {
                        var extension = Path.GetExtension(RModel.Photo.FileName).ToLower();
                        if (extension != ".jpg")
                        {
                            ModelState.AddModelError("RModel.Photo", "Only .JPG files are allowed.");
                            return Page();
                        }

                        var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads");
                        Directory.CreateDirectory(uploadsFolder);
                        string uniqueFileName = Guid.NewGuid().ToString() + extension;
                        string filePath = Path.Combine(uploadsFolder, uniqueFileName);

                        using (var fileStream = new FileStream(filePath, FileMode.Create))
                        {
                            await RModel.Photo.CopyToAsync(fileStream);
                        }

                        photoPath = "/uploads/" + uniqueFileName;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error uploading profile photo.");
                        ModelState.AddModelError("RModel.Photo", "Error uploading the profile picture.");
                        return Page();
                    }
                }

                // Encode all user inputs before storing in the database
                string encodedFirstName = EncodeInput(RModel.FirstName);
                string encodedLastName = EncodeInput(RModel.LastName);
                string encodedBillingAddress = EncodeInput(RModel.BillingAddress);
                string encodedShippingAddress = EncodeInput(RModel.ShippingAddress);

                // Generate salt and hash password
                GenerateSaltAndHash(RModel.Password, out string hashedPassword, out string salt);
                string encryptedCreditCard = EncryptData(RModel.CreditCardNo);
                string sessionToken = GenerateSessionToken();

                var user = new ApplicationUser
                {
                    FirstName = encodedFirstName,
                    LastName = encodedLastName,
                    CreditCardNo = encryptedCreditCard,
                    MobileNo = RModel.MobileNo,
                    BillingAddress = encodedBillingAddress,
                    ShippingAddress = encodedShippingAddress,
                    Email = EncodeInput(RModel.Email),
                    UserName = EncodeInput(RModel.Email),
                    PhotoPath = photoPath ?? null,
                    PasswordHash = hashedPassword, //Store hashed password
                    PasswordSalt = salt,           // Store generated salt
                    PreviousPasswordHash1 = hashedPassword,
                    PreviousPasswordHash2 = "",
                    LastPasswordChangeDate = DateTime.UtcNow,
                    SessionToken = sessionToken
                };


                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    HttpContext.Session.SetString("SessionToken", sessionToken);
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation("New user registered successfully.");
                    return RedirectToPage("Index");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during user registration.");
                return RedirectToPage("/Error/500");
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
                string pwdWithSalt = password + salt; // Concatenate password with salt
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

        private string EncryptData(string plainText)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = encryptionKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    {
                        byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
                        byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                        return Convert.ToBase64String(encryptedBytes);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Encryption failed.");
                return "EncryptionError";
            }
        }
    }
}
