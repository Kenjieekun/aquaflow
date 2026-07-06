import {
    auth,
    db
} from "./firebase-config.js";

import {
    doc,
    getDoc,
    setDoc
} from "https://www.gstatic.com/firebasejs/12.2.1/firebase-firestore.js";

// ========================================
// FIRESTORE
// ========================================

const settingsRef = doc(
    db,
    "settings",
    "system"
);

// ========================================
// SETTINGS ELEMENTS
// ========================================

const systemName = document.getElementById("systemName");
const businessName = document.getElementById("businessName");
const businessEmail = document.getElementById("businessEmail");
const businessPhone = document.getElementById("businessPhone");
const businessAddress = document.getElementById("businessAddress");

const lowStockAlert = document.getElementById("lowStockAlert");
const archiveDays = document.getElementById("archiveDays");

const notifyNewOrders = document.getElementById("notifyNewOrders");
const notifyLowStock = document.getElementById("notifyLowStock");
const notifyCancelledOrders = document.getElementById("notifyCancelledOrders");

// ========================================
// BUTTONS
// ========================================

const saveSettingsBtn = document.getElementById("saveSettingsBtn");
const enableBiometricBtn = document.getElementById("enableBiometricBtn");

// ========================================
// OTP
// ========================================

const otpModal = document.getElementById("otpModal");
const otpInput = document.getElementById("otpInput");

const verifyOtpBtn = document.getElementById("verifyOtpBtn");
const cancelOtpBtn = document.getElementById("cancelOtpBtn");
const resendOtpBtn = document.getElementById("resendOtpBtn");

// ========================================
// TOAST
// ========================================

const toast = document.getElementById("toast");
const toastMessage = document.getElementById("toastMessage");

// ========================================
// LOAD SETTINGS
// ========================================

async function loadSettings() {

    try {

        const snapshot = await getDoc(settingsRef);

        if (!snapshot.exists()) {
            return;
        }

        const settings = snapshot.data();

        systemName.value = settings.systemName || "";
        businessName.value = settings.businessName || "";
        businessEmail.value = settings.businessEmail || "";
        businessPhone.value = settings.businessPhone || "";
        businessAddress.value = settings.businessAddress || "";

        lowStockAlert.value = settings.lowStockAlert || 5;
        archiveDays.value = settings.archiveDays || 30;

        notifyNewOrders.checked = settings.notifyNewOrders ?? true;
        notifyLowStock.checked = settings.notifyLowStock ?? true;
        notifyCancelledOrders.checked = settings.notifyCancelledOrders ?? true;

    }

    catch (error) {

        console.error(error);

        showToast(
            "Unable to load settings.",
            "error"
        );

    }

}

// ========================================
// SAVE SETTINGS
// ========================================

async function saveSettings() {

    try {

        await setDoc(
            settingsRef,
            {
                systemName: systemName.value.trim(),
                businessName: businessName.value.trim(),
                businessEmail: businessEmail.value.trim(),
                businessPhone: businessPhone.value.trim(),
                businessAddress: businessAddress.value.trim(),

                lowStockAlert: Number(lowStockAlert.value),
                archiveDays: Number(archiveDays.value),

                notifyNewOrders: notifyNewOrders.checked,
                notifyLowStock: notifyLowStock.checked,
                notifyCancelledOrders: notifyCancelledOrders.checked

            },
            {
                merge: true
            }
        );

        showToast("Settings saved successfully.");

    }

    catch (error) {

        console.error(error);

        showToast(
            "Unable to save settings.",
            "error"
        );

    }

}

// ========================================
// SEND OTP
// ========================================

saveSettingsBtn.addEventListener(
    "click",
    sendOtp
);

async function sendOtp() {

    saveSettingsBtn.disabled = true;
    saveSettingsBtn.textContent = "Sending OTP...";

    try {

        const response = await fetch(
            "/admin-panel/settings/send-otp/",
            {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCookie("csrftoken")
                }
            }
        );

        const result = await response.json();

        if (result.success) {

            otpModal.classList.add("show");
            otpInput.focus();

            startResendCountdown();

            showToast(
                "OTP sent successfully.",
                "info"
            );

        }

        else {

            showToast(
                result.message,
                "error"
            );

        }

    }

    catch (error) {

        console.error(error);

        showToast(
            "Unable to send OTP.",
            "error"
        );

    }

    saveSettingsBtn.disabled = false;
    saveSettingsBtn.textContent = "Save Settings";

}

// ========================================
// VERIFY OTP
// ========================================

verifyOtpBtn.addEventListener(
    "click",
    verifyOtp
);

async function verifyOtp() {

    const formData = new FormData();

    formData.append(
        "otp",
        otpInput.value.trim()
    );

    const response = await fetch(
        "/admin-panel/settings/verify-otp/",
        {
            method: "POST",
            headers: {
                "X-CSRFToken": getCookie("csrftoken")
            },
            body: formData
        }
    );

    const result = await response.json();

    if (!result.success) {

        showToast(
            result.message,
            "error"
        );

        return;

    }

    otpModal.classList.remove("show");
    otpInput.value = "";

    await saveSettings();

}

// ========================================
// CANCEL OTP
// ========================================

cancelOtpBtn.addEventListener(
    "click",
    () => {

        otpModal.classList.remove("show");
        otpInput.value = "";

    }
);

// ========================================
// RESEND OTP
// ========================================

resendOtpBtn.addEventListener(
    "click",
    sendOtp
);

function startResendCountdown() {

    let seconds = 60;

    resendOtpBtn.disabled = true;
    resendOtpBtn.textContent = `Resend OTP (${seconds}s)`;

    const timer = setInterval(() => {

        seconds--;

        resendOtpBtn.textContent = `Resend OTP (${seconds}s)`;

        if (seconds <= 0) {

            clearInterval(timer);

            resendOtpBtn.disabled = false;
            resendOtpBtn.textContent = "Resend OTP";

        }

    }, 1000);

}

// ========================================
// BIOMETRICS
// ========================================

enableBiometricBtn.addEventListener(
    "click",
    registerBiometric
);

function base64urlToUint8Array(base64url) {

    const padding =
        "=".repeat((4 - base64url.length % 4) % 4);

    const base64 =
        (base64url + padding)
            .replace(/-/g, "+")
            .replace(/_/g, "/");

    const binary =
        atob(base64);

    return Uint8Array.from(
        binary,
        character => character.charCodeAt(0)
    );

}

function bufferToBase64url(buffer) {

    const bytes = new Uint8Array(buffer);

    let binary = "";

    bytes.forEach(byte => {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");

}

async function registerBiometric() {

    try {

        const currentUser = auth.currentUser;

        if (!currentUser) {

            showToast(
                "Please login first.",
                "error"
            );

            return;

        }

        // Begin registration
        const beginResponse = await fetch(
            "/webauthn/register/begin/",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": getCookie("csrftoken")
                },
                body: JSON.stringify({
                    firebaseUid: currentUser.uid,
                    email: currentUser.email,
                    displayName:
                        currentUser.displayName ||
                        "Aqua Admin"
                })
            }
        );

        const options = await beginResponse.json();

        if (!beginResponse.ok) {

            throw new Error(
                options.message ||
                "Unable to begin registration."
            );

        }

        options.challenge =
            base64urlToUint8Array(options.challenge);

        options.user.id =
            base64urlToUint8Array(options.user.id);

        if (options.excludeCredentials) {

            options.excludeCredentials =
                options.excludeCredentials.map(
                    credential => ({
                        ...credential,
                        id: base64urlToUint8Array(
                            credential.id
                        )
                    })
                );

        }

        // Create credential
        const credential =
            await navigator.credentials.create({
                publicKey: options
            });

        // Finish registration
        const finishResponse = await fetch(
            "/webauthn/register/finish/",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": getCookie("csrftoken")
                },
                body: JSON.stringify({

                    id: credential.id,

                    rawId: bufferToBase64url(
                        credential.rawId
                    ),

                    type: credential.type,

                    response: {

                        clientDataJSON:
                            bufferToBase64url(
                                credential.response.clientDataJSON
                            ),

                        attestationObject:
                            bufferToBase64url(
                                credential.response.attestationObject
                            )

                    }

                })
            }
        );

        const result =
            await finishResponse.json();

        if (!finishResponse.ok || !result.success) {

            throw new Error(
                result.message ||
                "Registration failed."
            );

        }

        showToast(
            "Biometric registered successfully."
        );

    }

    catch (error) {

        console.error(error);

        showToast(
            error.message ||
            "Biometric registration failed.",
            "error"
        );

    }

}

// ========================================
// TOAST
// ========================================

function showToast(message, type = "success") {

    toast.className = `toast ${type} show`;

    toastMessage.textContent = message;

    setTimeout(() => {

        toast.classList.remove("show");

    }, 3000);

}

// ========================================
// CSRF
// ========================================

function getCookie(name) {

    let cookieValue = null;

    if (document.cookie && document.cookie !== "") {

        const cookies = document.cookie.split(";");

        for (const cookie of cookies) {

            const value = cookie.trim();

            if (value.startsWith(name + "=")) {

                cookieValue = decodeURIComponent(
                    value.substring(name.length + 1)
                );

                break;

            }

        }

    }

    return cookieValue;

}

// ========================================
// INITIALIZE
// ========================================

loadSettings();