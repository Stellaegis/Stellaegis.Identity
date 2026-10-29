// Stellaegis.Identity.Server — what the pages do in the browser: the strength meter of a new password, the time
// zone of the browser, the avatar editor, and the QR code of an authenticator enrollment. Nothing here decides
// anything: the server checks again.
(function () {
    "use strict";

    // The strength meter mirrors the scoring of the module: the length first, six points per character past the
    // sixth up to 70, then a bonus for what the password mixes (upper 8, lower 5, digit 7, special 10): weak under
    // 25, fair under 55, strong under 80, very strong above. The server checks the policy and the blocklist again.
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
            var length = Math.min(Math.max((pwd.length - 6) * 6, 0), 70);
            var upper = /[A-Z]/.test(pwd) ? 8 : 0;
            var lower = /[a-z]/.test(pwd) ? 5 : 0;
            var digit = /[0-9]/.test(pwd) ? 7 : 0;
            var special = /[^a-zA-Z0-9]/.test(pwd) ? 10 : 0;
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

    // The time zone of the browser: written into a hidden field of the registration ("fill"), only suggested on the
    // account ("suggest"), where an empty field is a choice — the button takes the browser's when the person wants it.
    var zone = window.Intl && Intl.DateTimeFormat ? Intl.DateTimeFormat().resolvedOptions().timeZone : "";
    if (zone) {
        document.querySelectorAll("input[data-browser-time-zone]").forEach(function (field) {
            if (field.dataset.browserTimeZone === "fill") {
                field.value = zone;
            } else if (!field.value) {
                field.placeholder = zone;
            }
        });
        document.querySelectorAll("button[data-use-browser-time-zone]").forEach(function (button) {
            var field = document.getElementById(button.dataset.useBrowserTimeZone);
            if (!field || field.value === zone) return;
            button.textContent = button.textContent + " (" + zone + ")";
            button.hidden = false;
            button.addEventListener("click", function () { field.value = zone; button.hidden = true; });
        });
    }

    // The avatar editor: an image from a file or from Gravatar, moved and zoomed under a circular mask, exported as
    // a PNG of 256 by 256 pixels into the form. The server checks the PNG again and keeps only what draws it.
    var editor = document.querySelector("[data-avatar-editor]");
    if (editor) {
        var crop = editor.querySelector("[data-avatar-crop]");
        var canvas = editor.querySelector("[data-avatar-canvas]");
        var context = canvas.getContext("2d");
        var zoom = editor.querySelector("[data-avatar-zoom]");
        var message = editor.querySelector("[data-avatar-message]");
        var viewport = editor.querySelector("[data-avatar-viewport]");
        var side = canvas.width;
        var image = null, base = 1, scale = 1, x = 0, y = 0, drag = null;

        var say = function (text) { message.textContent = text || ""; message.hidden = !text; };
        var clamp = function () {
            x = Math.min(0, Math.max(side - image.width * scale, x));
            y = Math.min(0, Math.max(side - image.height * scale, y));
        };
        var draw = function () {
            context.clearRect(0, 0, side, side);
            context.imageSmoothingQuality = "high";
            context.drawImage(image, x, y, image.width * scale, image.height * scale);
        };
        var load = function (loaded) {
            if (!loaded.width || !loaded.height) { say(editor.dataset.errorRead); return; }
            image = loaded;
            base = Math.max(side / image.width, side / image.height);
            scale = base;
            zoom.value = "1";
            x = (side - image.width * scale) / 2;
            y = (side - image.height * scale) / 2;
            say("");
            crop.hidden = false;
            draw();
            viewport.focus();
        };
        var open = function (source, failure, crossOrigin) {
            var loading = new Image();
            if (crossOrigin) loading.crossOrigin = "anonymous";
            loading.onload = function () { load(loading); };
            loading.onerror = function () { say(failure); };
            loading.src = source;
        };

        editor.querySelector("[data-avatar-file]").addEventListener("change", function () {
            var file = this.files && this.files[0];
            if (!file) return;
            var url = URL.createObjectURL(file);
            open(url, editor.dataset.errorRead, false);
            this.value = "";
            setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
        });

        var gravatar = editor.querySelector("[data-avatar-gravatar]");
        if (gravatar && window.crypto && crypto.subtle) {
            gravatar.addEventListener("click", function () {
                var address = editor.querySelector("[data-avatar-gravatar-email]").value.trim().toLowerCase();
                if (!address) return;
                crypto.subtle.digest("SHA-256", new TextEncoder().encode(address)).then(function (digest) {
                    var hash = Array.prototype.map.call(new Uint8Array(digest), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
                    open("https://gravatar.com/avatar/" + hash + "?s=512&d=404", editor.dataset.errorGravatar, true);
                });
            });
        }

        zoom.addEventListener("input", function () {
            var previous = scale;
            scale = base * parseFloat(zoom.value);
            x = side / 2 - (side / 2 - x) * scale / previous;
            y = side / 2 - (side / 2 - y) * scale / previous;
            clamp();
            draw();
        });
        canvas.addEventListener("pointerdown", function (event) {
            if (!image) return;
            drag = { x: event.clientX, y: event.clientY };
            canvas.setPointerCapture(event.pointerId);
        });
        canvas.addEventListener("pointermove", function (event) {
            if (!drag) return;
            var ratio = side / canvas.clientWidth;
            x += (event.clientX - drag.x) * ratio;
            y += (event.clientY - drag.y) * ratio;
            drag = { x: event.clientX, y: event.clientY };
            clamp();
            draw();
        });
        canvas.addEventListener("pointerup", function () { drag = null; });
        canvas.addEventListener("pointercancel", function () { drag = null; });
        viewport.addEventListener("keydown", function (event) {
            if (!image) return;
            var moves = { ArrowLeft: [8, 0], ArrowRight: [-8, 0], ArrowUp: [0, 8], ArrowDown: [0, -8] };
            var move = moves[event.key];
            if (!move) return;
            event.preventDefault();
            x += move[0];
            y += move[1];
            clamp();
            draw();
        });
        crop.addEventListener("submit", function () {
            crop.querySelector("[data-avatar-image]").value = canvas.toDataURL("image/png");
        });
        editor.querySelector("[data-avatar-cancel]").addEventListener("click", function () {
            crop.hidden = true;
            image = null;
            say("");
        });
    }

    // The QR code of an enrollment, drawn by qrcode.min.js when the page loads it.
    var qr = document.querySelector(".auth-qr[data-qr]");
    if (qr && typeof QRCode === "function") {
        new QRCode(qr, { text: qr.dataset.qr, width: 180, height: 180, colorDark: "#000000", colorLight: "#ffffff" });
    }
})();
