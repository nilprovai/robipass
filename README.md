# Roblox JoinGame Captcha Bypass

A fast, lightweight script designed to automatically bypass the captcha barrier when joining Roblox games.
**Developed by nilcute!!** (Discord: `1207080226019086438`)

---
## Installation & Usage

### Prerequisites
Make sure you have [Python](https://www.python.org/downloads/) installed on your system.

### Step-by-Step Tutorial
**1. Install dependencies**
Open your terminal or command prompt in the project folder and run the following command to install the required libraries:
```bash
pip install -r requirements.txt

```

**2. Run the script**

Start the bypass tool by running the main Python file:

```bash
py main.py

```

*(Note: depending on your Python installation, you might need to use `python main.py` or `python3 main.py`)*

**3. Launch Roblox**

Once the script is running in the background, simply launch Roblox and join a game. The tool will handle the captcha automatically!

## How It Works
Under the hood, the script uses a Man-in-the-Middle (MITM) approach combined with memory patching to reroute the join requests seamlessly:
1.  **Proxy Initialization:** It spins up a `mitmproxy` instance specifically targeting the `RobloxPlayerBeta.exe` process.
2.  **Traffic Routing:** All network requests destined for `gamejoin.roblox.com` are forced through this proxy.
3.  **Process Patching & Certificate Injection:** It continuously scans for active Roblox processes. Once detected, it directly patches the process to inject the `mitmproxy` SSL certificate. This forces Roblox to accept the proxy's certificate as valid, preventing connection drops or SSL pinning blocks.
4.  **Endpoint Redirection:** Finally, it intercepts any requests made to the `/v1/join-game` endpoint and forwards them to `/v1/join-play-together-game`, which effectively bypasses the captcha requirement.

---

## ⚠️ Disclaimer

This tool is provided as-is for educational and personal use. Use it responsibly at your own risk. The developer is not responsible for any actions taken against your Roblox account.

## Support the Developer

I built this tool for free, but I am currently completely broke and struggling to get by. If this script helped you out and saved you time, please consider tossing a small donation my way so I can afford a meal today. Every single cent genuinely helps keep me going!

### 🪙 Cryptocurrency Wallets

* **LTC:** `ltc1q5tuvtt6cxt96k077fuaq3zd0wk3hmsylsyxldx`
* **ETH:** `0x9C827E8c69B52b9faADE1B48fD1Fdc90210f97e2`
* **BTC:** `bc1qv64x0krfl2dl8gtjnkxdwreq8j56k0qxghvyv6`

### 🏦 Bank Transfer (Vietnam Only)

* **Bank:** MBBank
* **Account Number:** `102793`
* **Account Name:** NGUYEN VAN BANG

---

*If you found this helpful, please drop a ⭐ on the repository!*
*For any questions, please DM me on Discord!*