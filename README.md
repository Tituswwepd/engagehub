# EngageHubCoin 🎉

EngageHubCoin is a full-stack reward platform where users can:

- ✅ Earn by completing **surveys and offers** (CPX, BitLabs, AdGem, Tapjoy, etc.)
- 💸 **Deposit & Withdraw** using **PayPal** (balance or credit/debit card)
- 📱 Connect and interact with **WhatsApp, TikTok, Facebook, Instagram, X (Twitter), YouTube**
- 📻 Listen to **Radio stations** (auto-scanner built in)
- 🤖 Play **AI-powered quiz games**
- 🏢 Integrate with up to **20+ Data Buyer/Offerwall networks**

---

## Features

- **Wallet System**: Tracks survey earnings and deposits  
- **Hidden Rule**: Only 50% of survey earnings are withdrawable (server-side enforced)  
- **PayPal Integration**: Deposits and payouts automated with PayPal REST APIs  
- **Social APIs**:
  - WhatsApp Messaging (Meta Cloud API)
  - TikTok OAuth (login/connect)
  - Facebook OAuth (login/connect)
  - YouTube latest channel videos
  - Instagram Post/Reel embedding
  - X (Twitter) embed support
- **AI Quiz**: Uses OpenAI API if available, otherwise local question bank
- **Admin Panel**: Check users, wallets, and withdrawal requests

---

## Deployment (Render)

1. Push code to GitHub  
2. Render detects `render.yaml` and sets up:
   - Node.js service
   - Persistent disk `/var/data` for SQLite DB
   - Port = 10000  
3. Set **environment variables** in Render Dashboard:
   - `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`
   - `META_ACCESS_TOKEN`, `META_VERIFY_TOKEN`, `WHATSAPP_PHONE_NUMBER_ID`
   - `FB_APP_ID`, `FB_APP_SECRET`, `FB_REDIRECT_URI`
   - `TIKTOK_CLIENT_KEY`, `TIKTOK_CLIENT_SECRET`, `TIKTOK_REDIRECT_URI`
   - `YOUTUBE_API_KEY`, `YOUTUBE_CHANNEL_ID`
   - `OPENAI_API_KEY` (optional)

---

## Local Development

```bash
git clone https://github.com/<your-username>/engagehubcoin.git
cd engagehubcoin
npm install
npm start
