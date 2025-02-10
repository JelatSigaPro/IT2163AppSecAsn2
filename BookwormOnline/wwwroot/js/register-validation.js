$(document).ready(function () {
    // Validate Password Complexity
    $("#RModel_Password").on("input", function () {
        var password = $(this).val();
        var strengthMessage = "";

        // Password Complexity Checks
        var hasLower = /[a-z]/.test(password);
        var hasUpper = /[A-Z]/.test(password);
        var hasNumber = /\d/.test(password);
        var hasSpecial = /[$@$!%*?&]/.test(password);
        var minLength = password.length >= 12;

        // Determine Password Strength
        var strength = 0;
        if (hasLower) strength++;
        if (hasUpper) strength++;
        if (hasNumber) strength++;
        if (hasSpecial) strength++;
        if (minLength) strength++;

        // Provide Feedback to User
        if (strength === 5) {
            strengthMessage = "<span class='text-success'>Strong ✅</span>";
        } else if (strength >= 3) {
            strengthMessage = "<span class='text-warning'>Medium ⚠️</span>";
        } else {
            strengthMessage = "<span class='text-danger'>Weak ❌</span>";
        }

        // Display Feedback
        $("#passwordStrength").html(strengthMessage);
    });

    // Prevent form submission if password is weak
    $("form").submit(function (e) {
        if ($("#passwordStrength").text().includes("Weak")) {
            alert("Password is too weak. Please improve it before submitting.");
            e.preventDefault();
        }
    });
});
