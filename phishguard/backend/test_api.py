import requests

test_urls = [
    # 1. Official / Safe websites
    "https://www.goog1e.com",
    "https://www.paypaI.com",
    "https://www.app1e.com",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://www.facebook.com",
    "https://www.netf1ix.com",
    "https://www.maybank2U.com.my",

    # 2. Brand impersonation
    "https://paypal-login-securIty.com",
    "https://google-account-verify.net",
    "https://apple-id-confirmation.com",
    "https://microsoft-security-update.xyz",
    "https://amazon-payment-confirm.com",
    "https://facebook-login-alert.com",
    "https://netflix-account-suspend.com",

    # 3. Malaysian banking / e-wallet imitation
    "https://maybank-login-security.com",
    "https://secure-cimb-verification.net",
    "https://rhb-account-update.com",
    "https://touchngo-wallet-update.corn",
    "https://tng-payment-confirm.corn",

    # 4. Technical phishing indicators
    "http://192.168.1.10/login",
    "http://paypal.com@evil-site.ru/login",
    "http://secure-update-account-login.corn",
    "https://verify-account-payment-login.net",
    "http://bank-login-confirm-update.xyz",

    # 5. Suspicious but no famous brand
    "https://pay-login-security.com",
    "https://account-verification-center.net",
    "https://secure-wallet-update.info",
    "https://password-reset-confirmation.xyz",
    "https://login-support-limited.com"
]

def main():
    for i, url in enumerate(test_urls, start=1):
        response = requests.post(
            "http://127.0.0.1:5000/predict",
            json={"url": url}
        )

        result = response.json()

        print("\n==============================")
        print(f"No. {i}")
        print("URL:", url)
        print("Result:", result["result"])
        print("Risk Score:", result["risk_score"])
        print("Explanation:", result["explanations"])


if __name__ == "__main__":
    main()
