# Deployment Instructions

Follow these steps to deploy and configure your Telegram Test Card Generator Bot.

## 1. Prerequisites

*   A [Cloudflare account](https://dash.cloudflare.com/sign-up).
*   [Node.js](https://nodejs.org/) and [npm](https://www.npmjs.com/) installed.
*   A Telegram bot token from [@BotFather](https://t.me/BotFather).

## 2. Install Wrangler CLI

If you don't have the Wrangler CLI installed, open your terminal and run:

```bash
npm install -g wrangler
```

## 3. Deploy the Worker

In your terminal, navigate to the `telegram-cc-gen-bot` directory and run the following command to deploy your worker:

```bash
npm run deploy
```

This command will bundle and upload your worker to the Cloudflare network. After the first deployment, you will get a unique URL for your worker (e.g., `https://telegram-cc-gen-bot.<YOUR_SUBDOMAIN>.workers.dev`).

## 4. Set the Telegram Bot Token

To keep your bot token secure, we'll store it as a secret in your Cloudflare Worker. Run the following command in your terminal, replacing `<YOUR_BOT_TOKEN>` with the token you got from BotFather:

```bash
wrangler secret put TELEGRAM_BOT_TOKEN
```

You will be prompted to enter the token value in your terminal.

## 5. Set the Webhook

The final step is to tell Telegram where to send updates. We'll do this by setting a webhook, which points to your new worker's URL.

Take the URL from your worker deployment and append `/webhook` to it. Then, run the following command in your terminal, replacing `<YOUR_WORKER_URL>` with your full worker URL:

```bash
curl "https://<YOUR_WORKER_URL>/set-webhook?url=https://<YOUR_WORKER_URL>/webhook"
```

You should see a message confirming that the webhook was set successfully.

Your bot is now live and ready to use!
