# SentinelSphere Test Data

Use these URLs and email samples to test the detection capabilities of SentinelSphere.

## 🟢 Normal / Safe URLs
These should be classified as **SAFE**.

1. `https://www.google.com` - Standard search engine
2. `https://github.com/Shivamborn2shine/PBL-4th-Sem` - This project's repo
3. `https://www.amazon.com/gp/product/B08` - Standard e-commerce link
4. `https://stackoverflow.com/questions/123456/how-to-test` - Developer community
5. `https://en.wikipedia.org/wiki/Computer_security` - Informational site
6. `https://www.nytimes.com/section/technology` - News site
7. `https://discord.com/app` - Web application

## 🔴 Malicious / Phishing URLs
These should be classified as **HIGH RISK** or **SUSPICIOUS**.
*Note: These are safe-to-click simulations or defanged examples.*

1. `http://suspicious-login.tk/verify?user=test@bank.com` - Suspicious TLD (.tk) + keywords
2. `http://192.168.1.55/admin/login.php` - IP address usage (often local/internal but flagged if public)
3. `https://secure-update-account-verification.xyz/login` - Keyword stuffing + suspicious TLD
4. `http://paypal-secure-check.com.bad-site.net/auth` - Subdomain spoofing
5. `https://apple-id-verify.support-center.ga/index.html` - Brand impersonation + suspicious TLD
6. `http://free-prize-claim.win/winner?id=12345` - "Free prize" scam pattern
7. `http://0x58.0xCC.0xCA.0x62` - Obfuscated IP address format

## 🟠 Suspicious / Borderline URLs
These might be classified as **SUSPICIOUS** depending on the model's confidence.

1. `http://bit.ly/3x8j9k2` - URL shortener (often flagged as suspicious until resolved)
2. `https://www.google.com@evil-site.com` - URL redirection/confusion attack
3. `http://login.example.com.evil.ru` - Homograph/subdomain trickery
4. `https://update-security.info` - Generic security domain (often used for scares)

## 📧 Phishing Email Samples
Paste these into the **Email Scan** tab.

### Sample 1: "Urgent Account Suspension" (High Risk)
```text
URGENT: Your account has been suspended due to suspicious activity!
Click here immediately to restore access: http://secure-bank-login.tk/verify
If you do not update your payment information within 24 hours, your account will be permanently closed.
Enter your credit card details to confirm your identity.
ACT NOW!
```

### Sample 2: "Lottery Winner" (High Risk)
```text
CONGRATULATIONS! You have won the $5,000,000 lottery!
To claim your prize, please send your bank details and a processing fee of $500 to our agent.
Click here to claim: http://lottery-winner-claim.xyz
Don't tell anyone! This is a secret prize.
```

### Sample 3: "Normal Meeting Invite" (Safe)
```text
Hi Team,
Just a reminder that we have our weekly sprint planning meeting tomorrow at 10 AM.
Please review the attached documents and update your Jira tickets beforehand.
Here is the Zoom link: https://zoom.us/j/123456789
Best,
Project Manager
```

### Sample 4: "Password Reset Request" (Suspicious/Borderline)
```text
Someone requested a password reset for your account.
If this was you, click the link below to set a new password.
If you didn't ask for this, you can safely ignore this email.
https://myservice.com/reset-password?token=abc123456
```
