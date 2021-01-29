function myFunction() {
    var x = document.getElementById("input-otp");
    if (x.type === "password") {
        x.type = "text";
    } else {
        x.type = "password";
    }
};