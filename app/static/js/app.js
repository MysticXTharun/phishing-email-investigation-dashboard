document.addEventListener("DOMContentLoaded", () => {
    const scoreBars = document.querySelectorAll(".score-fill");

    scoreBars.forEach((bar) => {
        const score = Math.min(Number(bar.dataset.score) || 0, 100);
        bar.style.width = `${score}%`;

        if (score >= 70) {
            bar.style.backgroundColor = "#ef4444";
        } else if (score >= 40) {
            bar.style.backgroundColor = "#f59e0b";
        } else {
            bar.style.backgroundColor = "#22c55e";
        }
    });

    const emailInput = document.getElementById("raw_email");
    const loadSampleButton = document.getElementById("load-sample");
    const clearButton = document.getElementById("clear-email");

    const sampleEmail = `From: Microsoft Security <security@microsoft-support.example>
Reply-To: account-verify@malicious.example
Return-Path: <bounce@malicious.example>
To: employee@company.example
Subject: Urgent Security Alert - Verify Your Password
Message-ID: <phishing-001@malicious.example>
Authentication-Results: mail.company.example; spf=fail; dkim=fail; dmarc=fail
Received: from 185.234.219.45 by mail.company.example

Dear User,

We detected suspicious activity on your account. Your access will be suspended.

Click here immediately to verify your password:
https://malicious.example/login

Security Team`;

    if (emailInput && loadSampleButton) {
        loadSampleButton.addEventListener("click", () => {
            emailInput.value = sampleEmail;
            emailInput.focus();
        });
    }

    if (emailInput && clearButton) {
        clearButton.addEventListener("click", () => {
            emailInput.value = "";
            emailInput.focus();
        });
    }
});
