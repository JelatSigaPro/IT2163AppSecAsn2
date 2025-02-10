using BookwormOnline.Model;
using BookwormOnline.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages()
    .AddMvcOptions(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()); // ? Enforce CSRF Protection Globally
}); ;
builder.Services.AddScoped<IEmailSender, EmailSender>(); // ? Register Email Service
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // Lockout duration
    options.Lockout.MaxFailedAccessAttempts = 3; // Max failed attempts before lockout
    options.Lockout.AllowedForNewUsers = true; // Apply lockout policy to all users
})
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// ? Enable session services
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(15); // ? Set session timeout to 15 minutes
    options.Cookie.HttpOnly = true; // ? Prevent JavaScript access (mitigate XSS attacks)
    options.Cookie.IsEssential = true; // ? Ensure session is active even with GDPR restrictions
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error/500"); // Handles server-side exceptions
    app.UseHsts();
}

app.UseStatusCodePages(async context =>
{
    var response = context.HttpContext.Response;
    if (response.StatusCode == 404)
    {
        response.Redirect("/error/404"); // Handles page not found errors
    }
    else if (response.StatusCode == 403)
    {
        response.Redirect("/error/403"); // Handles access denied errors
    }
    else if (response.StatusCode == 400)
    {
        response.Redirect("/error/400"); // Handles access denied errors
    }
    else
    {
        response.Redirect("/error/500"); // Handles all other errors
    }
});



app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// ? Enable session middleware
app.UseSession();

app.MapRazorPages();

app.Run();
