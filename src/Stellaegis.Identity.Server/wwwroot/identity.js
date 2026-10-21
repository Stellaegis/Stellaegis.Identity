// Stellaegis.Identity.Server — what the pages do in the browser: the strength meter of a new password, and the
// QR code of an authenticator enrollment. Nothing here decides anything: the server checks the policy again.
(function () {
    "use strict";

    // The strength meter mirrors the scoring of the module (length up to 40, upper 15, lower 10, digit 15,
    // special 20): weak under 25, fair under 55, strong under 80, very strong above.
    var input = document.querySelector("input[data-min-length]");
    if (input) {
        var minLength = parseInt(input.dataset.minLength || "8", 10);
        var requireUpper = input.dataset.requireUpper === "true";
        var requireLower = input.dataset.requireLower === "true";
        var requireDigit = input.dataset.requireDigit === "true";
        var requireSpecial = input.dataset.requireSpecial === "true";
        var labels = (input.dataset.labels || "Weak|Fair|Strong|Very strong").split("|");
        var field = input.closest(".auth-field");
        var fill = field && field.querySelector(".pwd-strength-fill");
        var text = field && field.querySelector(".pwd-strength-text");

        var score = function (pwd) {
            var length = Math.min(Math.max((pwd.length - 4) * 3, 0), 40);
            var upper = /[A-Z]/.test(pwd) ? 15 : 0;
            var lower = /[a-z]/.test(pwd) ? 10 : 0;
            var digit = /[0-9]/.test(pwd) ? 15 : 0;
            var special = /[^a-zA-Z0-9]/.test(pwd) ? 20 : 0;
            return Math.min(length + upper + lower + digit + special, 100);
        };
        var meetsPolicy = function (pwd) {
            if (pwd.length < minLength) return false;
            if (requireUpper && !/[A-Z]/.test(pwd)) return false;
            if (requireLower && !/[a-z]/.test(pwd)) return false;
            if (requireDigit && !/[0-9]/.test(pwd)) return false;
            if (requireSpecial && /^[a-zA-Z0-9]*$/.test(pwd)) return false;
            return true;
        };
        var levels = [
            { min: 80, color: "#1f6f3a", label: labels[3], width: "100%" },
            { min: 55, color: "#5aa469", label: labels[2], width: "75%" },
            { min: 25, color: "#d9981a", label: labels[1], width: "50%" },
            { min: 0, color: "#a4262c", label: labels[0], width: "25%" }
        ];
        if (fill && text) {
            input.addEventListener("input", function () {
                var pwd = this.value;
                if (!pwd) { fill.style.width = "0"; text.textContent = ""; return; }
                var s = score(pwd);
                if (!meetsPolicy(pwd) && s >= 55) s = 54;
                var level = levels.find(function (l) { return s >= l.min; });
                fill.style.width = level.width;
                fill.style.background = level.color;
                text.textContent = level.label;
                text.style.color = level.color;
            });
        }
    }

    // The QR code of an enrollment, drawn by qrcode.min.js when the page loads it.
    var qr = document.querySelector(".auth-qr[data-qr]");
    if (qr && typeof QRCode === "function") {
        new QRCode(qr, { text: qr.dataset.qr, width: 180, height: 180, colorDark: "#000000", colorLight: "#ffffff" });
    }
})();
