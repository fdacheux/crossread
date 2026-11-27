# CrossRead — Step-by-Step Beginner Deployment Guide ($0/month)

This guide walks you through publishing **CrossRead** online from start to finish. It is written for junior developers or anyone deploying a web app for the first time—every click, secret, and common mistake is explained clearly.

---

## How the App Works (Big Picture)

Your app has **3 small pieces** that talk to each other:

1. **GitHub Actions (The Daily Robot):** Wakes up every morning at 07:00 CET, fetches English & French cybersecurity news, asks Gemini AI to create clean summaries, and saves them to the database.
2. **Supabase (The Database & Owner Login):** Stores the briefings, your watchlist keywords, and checks whether you are the owner when you turn email alerts On/Off.
3. **Vercel (The Website):** Hosts the public dashboard (`https://your-app.vercel.app`) that reads briefings from Supabase.

> **Quick Glossary for Beginners**
> - **API Key / Secret:** Like a private password that lets one service talk to another. Never paste secrets into code files or send them in chat.
> - **SQL Migration:** A text script that creates tables and security rules inside your database.
> - **Root Directory:** The specific folder inside your repository that Vercel should build. For this app, the production website lives in the **`web`** folder (not the top-level preview folder).

---

## Before You Start: Create 4 Free Accounts (~10 minutes)

| Service | What it does | Link | Required? |
| :--- | :--- | :--- | :--- |
| **GitHub** | Stores your code & runs the daily news robot | https://github.com | Yes |
| **Supabase** | Free PostgreSQL database & owner sign-in | https://supabase.com | Yes |
| **Google AI Studio** | Free Gemini API key for summarizing articles | https://aistudio.google.com | Yes |
| **Vercel** | Puts your website live on HTTPS | https://vercel.com | Yes |
| **Resend** | Sends your optional daily owner email digest | https://resend.com | Optional |

---

## Step 1 — Put Your Code on GitHub

1. Sign in to **GitHub** and click **+** (top right) → **New repository**.
2. Name it `crossread`, choose **Private** or **Public**, and click **Create repository** *(leave "Add a README" unchecked)*.
3. Open a terminal inside your project folder and run:

```bash
git init
git add .
git commit -m "Initial CrossRead deployment"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/crossread.git
git push -u origin main
```

*(Not comfortable with the terminal? You can also upload the folder using **GitHub Desktop**.)*

---

## Step 2 — Set Up the Database & Owner Account (Supabase)

### 2A. Create the Project
1. Log in to **Supabase** → click **New project**.
2. Name it `crossread`, generate a strong database password (save it somewhere safe), and choose an **EU region** (such as **West EU — Paris** or **Central EU — Frankfurt**) for RGPD best practices.
3. Wait ~2 minutes for the database to finish starting.

### 2B. Create the Tables (Run the 4 SQL Migrations in Order)
1. In the left sidebar of Supabase, click **SQL Editor** → **New query**.
2. Open **`supabase/migrations/0001_phase1_schema.sql`** from your project, copy **all** of its text, paste it into the SQL Editor, and click **Run**. You should see `Success`.
3. Repeat for **`supabase/migrations/0002_phase2_owner_alerts.sql`** → click **Run**.
4. Repeat for **`supabase/migrations/0003_phase3_compliance_audit.sql`** → click **Run**.
5. Repeat for **`supabase/migrations/0004_pipeline_service_role_grants.sql`** → click **Run**.

### 2C. Create Your Pre-Registered Owner Account
For security, public visitors cannot sign up for accounts on the website. You create your single owner account directly inside Supabase:

1. Go to **Authentication → Providers → Email** and turn **OFF** *"Allow new users to sign up"*, then click **Save**.
2. Go to **Authentication → Users** → click **Add user → Create new user**.
   - Enter your email address (use **all lowercase**, e.g. `alex@example.com`).
   - Enter any random strong password (you will sign in with email magic links, so you won't need to type it daily).
   - Check **Auto Confirm User** (required so the security check verifies your email is confirmed).
   - Click **Create user**.
3. Go back to **SQL Editor** and register your email in the owner allowlist (replace with your exact lowercase email):

```sql
INSERT INTO public.admin_users (email) VALUES ('alex@example.com');
```

Click **Run**.

### 2D. Copy Your 3 Supabase Keys
Go to **Project Settings (gear icon) → API** and keep a temporary note of these 3 values:
- **Project URL** (looks like `https://abcdefghijkl.supabase.co`)
- **`anon` `public` key** — safe to put in your website (read-only access).
- **`service_role` `secret` key** — **MASTER KEY!** Never put this in Vercel or browser code. It goes **only** into GitHub Secrets in Step 6.

---

## Step 3 — Get Your Gemini API Key (and Optional Resend Key)

1. **Gemini API Key (Required):**
   - Go to https://aistudio.google.com/apikey.
   - Click **Create API key** and copy it (`GEMINI_API_KEY`).
2. **Resend API Key (Optional — only if you want daily email alerts):**
   - Sign up at https://resend.com using the **same email** you want alerts sent to.
   - Go to **API Keys → Create API Key** (permission: **Sending access**) and copy it (`RESEND_API_KEY`).
   - *Note:* On Resend's free tier without a custom domain, `onboarding@resend.dev` can only send emails to the email address registered on your Resend account.

---

## Step 4 — Publish the Website on Vercel

1. Log in to **Vercel** (sign in with GitHub) → click **Add New… → Project**.
2. Find your `crossread` repository and click **Import**.
3. **MOST IMPORTANT STEP — Set Root Directory:**
   - Look for **Root Directory** → click **Edit** → select **`web`** → click **Continue**.
   - *(Why? The root folder contains the local preview. The `web` folder contains the real Next.js production app.)*
4. Expand **Environment Variables** and add these **2** variables (and ONLY these 2):
   - `NEXT_PUBLIC_SUPABASE_URL` = your Supabase **Project URL**
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY` = your Supabase **`anon` `public` key**
5. Click **Deploy** and wait ~1–2 minutes.
6. Once finished, copy your live website URL (for example: `https://crossread.vercel.app`).

---

## Step 5 — Connect Your Live Vercel URL to Supabase Auth

Without this step, clicking your owner sign-in link in an email will try to redirect to `localhost` and fail.

1. Go to **Supabase → Authentication → URL Configuration**.
2. Set **Site URL** to your live Vercel URL:
   `https://crossread.vercel.app`
3. Under **Redirect URLs**, click **Add URL** and add:
   `https://crossread.vercel.app/**`
4. Click **Save**.

---

## Step 6 — Activate the Daily Automated Pipeline (GitHub Actions)

1. Open your repository on **GitHub** → go to **Settings → Secrets and variables → Actions**.
2. Stay on the **Secrets** tab and click **New repository secret** for each of these:

| Secret Name | Value | Required? |
| :--- | :--- | :--- |
| `SUPABASE_URL` | Your Supabase **Project URL** | Yes |
| `SUPABASE_SERVICE_ROLE_KEY` | Your Supabase **`service_role` secret key** | Yes |
| `GEMINI_API_KEY` | Your Google AI Studio key | Yes |
| `RESEND_API_KEY` | Your Resend API key | Optional (for email alerts) |
| `ALERT_RECIPIENT_EMAIL` | Your owner email address | Optional (for email alerts) |

3. Switch to the **Variables** tab (right next to Secrets) → click **New repository variable**:
   - Name: `DASHBOARD_URL`
   - Value: `https://crossread.vercel.app` *(your live Vercel URL)*

4. **Run the Pipeline Manually for the First Time:**
   - Click the **Actions** tab at the top of your GitHub repository.
   - Click **Daily Cybersecurity Briefing** in the left menu.
   - Click **Run workflow** (right side).
   - **Recommended first test:** Check **dry_run = true** and click **Run workflow**. Wait 2–4 minutes and make sure the run turns green.
   - **Real run:** Click **Run workflow** again with **dry_run = false**. When it finishes green, your database now has live briefings!

From now on, GitHub Actions will run automatically every morning at **07:00 CET (06:00 UTC)**.

---

## Step 7 — 2-Minute Go-Live Checklist

Open your live Vercel URL (`https://crossread.vercel.app`) and verify:

- [ ] Briefings appear on the page (wait up to 5 minutes after the first pipeline run or refresh).
- [ ] Category buttons, severity buttons, and the search box filter cards smoothly.
- [ ] Clicking **Privacy, RGPD & AI Notice** in the footer opens the compliance disclosure panel.
- [ ] Clicking **Owner alerts** → entering your owner email → clicking **Send sign-in link** sends you a magic link.
- [ ] After clicking the link in your email, you see the **Email alerts: Off** button in the header and can toggle it **On** or edit watchlist keywords in **Settings**.

---

## Quick Troubleshooting Guide

| Problem | Most Likely Cause | How to Fix |
| :--- | :--- | :--- |
| **Vercel build fails right away** | Root Directory was left as `.` instead of `web` | In Vercel → **Settings → General → Root Directory**, set it to `web` and redeploy. |
| **Website shows "No briefings match" / empty list** | Pipeline hasn't run with `dry_run = false` yet | Run **Daily Cybersecurity Briefing** in GitHub Actions with `dry_run` unchecked. |
| **Magic link redirects to `localhost:3000`** | Vercel URL wasn't added to Supabase Auth | Repeat **Step 5** (Site URL + Redirect URLs in Supabase). |
| **Signed in, but says "not registered in admin_users"** | Email missing, capitalized, or unconfirmed | Verify your user is confirmed in **Supabase → Authentication → Users** and run `INSERT INTO public.admin_users (email) VALUES ('your-lowercase-email');`. |
| **Owner alerts are On, but no email arrived** | Either no Critical/Watchlist stories matched, or Resend sender/recipient mismatch | Check `SELECT * FROM public.alert_logs ORDER BY sent_at DESC LIMIT 5;` in Supabase SQL Editor—the `status` and `error_message` columns tell you the exact reason. |
| **GitHub Action shows `429 RESOURCE_EXHAUSTED`** | Free-tier Gemini requests-per-minute hit a spike | Add a GitHub Repository Variable `LLM_THROTTLE_SECONDS` = `6.0` (slows requests slightly to stay comfortably under free limits). |
