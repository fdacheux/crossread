# Beginner-Friendly Test Plan (Junior QA Guide)

Welcome! This guide explains **what to test**, **how to test it step by step**, and **how to tell if something is broken** on the **Bilingual Cybersecurity Cross-Reader (CrossRead)** app.

You do not need deep coding knowledge to follow this plan.

---

## 1. How the App Works (In 4 Simple Steps)

1. **Every morning at 07:00 CET**, an automated script on GitHub reads 14 English and French cybersecurity news feeds.
2. **It turns each article into a short "Fact Sheet"** (just key facts like affected software, CVE codes, and fixes—never copying the full article).
3. **It groups articles about the same story together** (called a **Cluster**) and writes **one clear English briefing** shown on the public website.
4. **Optional Daily Email (Owner Only):** If the owner turns **Email alerts: On**, the app sends **1 daily summary email** for `Critical` alerts and watchlist keywords. If it is **Off**, zero emails are sent and anyone can simply read the website.

---

## 2. Quick Glossary (Plain English)

- **Briefing / Cluster:** One summary card on the website that combines 1 or more English/French articles about the same security event.
- **CVE:** An official ID number for a security bug (example: `CVE-2026-41892`).
- **Fact Sheet:** A small structured note of facts extracted from one article (no full copied text).
- **TNR (Non-Regression Tests):** Automated checks that re-run old tests every time developers change code, to make sure nothing that used to work got broken.
- **Dry Run:** A safe test run of the daily script that checks everything **without** saving anything to the real database or sending emails.

---

## 3. Before You Start Testing

- [ ] Open the app in **Chrome** (and also do a quick check in **Safari** or **Firefox** if available).
- [ ] Open your browser's **Developer Tools → Console** (`F12` or right-click → *Inspect* → *Console*). Keep an eye out for any **red error messages** while clicking around.
- [ ] Have a mobile-sized window ready (in DevTools, click the phone/tablet icon to test a 375px-wide mobile screen).

---

## 4. Step-by-Step Manual Test Cases

Mark each box `[x]` as you verify it.

### Part A: Browsing & Filtering the Dashboard

| ID | Test Name | Steps to Follow | Expected Result (PASS) |
| :--- | :--- | :--- | :--- |
| **TC-01** | Page loads cleanly | Open the home page. | Briefing cards appear with a headline, short summary, severity level, categories, source count, and date. No blank white screen and no red Console errors. |
| **TC-02** | Category filter | Click **Web/AppSec**, then **Regulations**, then **All**. | Only cards matching the clicked category stay visible. The counter (`Showing X of Y briefings`) updates every time. |
| **TC-03** | Severity filter | Click **Critical**, then **High**, then **All**. | Only cards with that exact severity level are shown. |
| **TC-04** | Top-right Critical shortcut | Click the dark **Critical (X)** button in the top bar. | Immediately filters the list to `Critical` briefings only. Clicking it again restores all severities. |
| **TC-05** | Search by CVE or word | Type `CVE-2026-41892` (or `CNIL`) into the search box. | Only matching briefings remain visible. |
| **TC-06** | Single search clear button | While text is typed in the search box, look at the right side of the input. Click the **X** button. | **Only ONE grey X** appears (never two crosses / no extra blue browser X). Clicking it empties the search box and restores all cards. |
| **TC-07** | No results & Reset | Type random text like `zzzznotfound999`. Click **Reset filters**. | A friendly "No briefings match these filters" message appears with a **Reset filters** button. Clicking it brings back all briefings. |

---

### Part B: Reading a Briefing Card & Deep Dive

| ID | Test Name | Steps to Follow | Expected Result (PASS) |
| :--- | :--- | :--- | :--- |
| **TC-08** | Expand & collapse Deep Dive | On any card, click **Show deep dive**, then click **Hide deep dive**. | Three sections open cleanly: **Technical details**, **Remediations**, and **Cross-source differences**. Clicking again hides them smoothly. |
| **TC-09** | Missing info is honest | Open a card where some details were not reported in the source news. | Missing fields explicitly say **`Not disclosed in sources`** (never empty broken boxes or made-up guesses). |
| **TC-10** | Bilingual source links | Click a source link (for example `CERT-FR Alertes [FR]` or `CISA KEV Catalog [EN]`). | The link opens in a **new browser tab** on an `https://` website. The dashboard tab stays open. |
| **TC-11** | Language readability | Read a briefing built from French sources (`[FR]`). | The headline, summary, technical details, and fixes are written in **clear, natural English** without garbled characters (like broken accents `Ã©`). |

---

### Part C: Owner-Only Email Alerts Toggle

| ID | Test Name | Steps to Follow | Expected Result (PASS) |
| :--- | :--- | :--- | :--- |
| **TC-12** | Public visitor view (Not signed in) | Open the site in an **Incognito / Private** window (not signed in). | You can read and filter all briefings normally. Near the top right you see **Owner alerts**, and you **cannot** switch emails On/Off or see any private settings. |
| **TC-13** | Default state is Off | Sign in with the owner email (or use **Owner view** in the preview). | By default, the button shows **Email alerts: Off** so nobody receives unwanted emails. |
| **TC-14** | One-click On / Off toggle | Click **Email alerts: Off**, refresh the page (on live site), then click **Email alerts: On** to turn it back off. | The button switches clearly between **Email alerts: On** (dark) and **Email alerts: Off** (white), and remembers your choice after refreshing. |
| **TC-15** | Watchlist keywords | Click **Alert settings** (or **Settings**), add a word like `Docker`, then click the small **X** next to it. | `Docker` is added to the list and removed cleanly when deleted. Very short 1-letter words are blocked. |
| **TC-16** | Non-owner cannot edit | *(Live site only)* Sign in with a random email that is **not** in `admin_users`. | The app displays a message that this account is not authorized and keeps everything read-only. |

---

### Part D: Security & Weird-Content Spot Checks

| ID | Test Name | Steps to Follow | Expected Result (PASS) |
| :--- | :--- | :--- | :--- |
| **TC-17** | Safe display of code snippets | Look at briefings mentioning HTML, XSS, or code (like `<script>`). | Code appears as **plain text**. No unexpected browser popup or broken page layout occurs. |
| **TC-18** | Manual URL safety check | *(GitHub Actions → Run workflow → `dry_run: true`)* Try submitting `http://example.com` or `https://127.0.0.1/test`. | The workflow logs reject the unsafe link (`SSRFBlockedError`) and do **not** fetch it. |
| **TC-19** | Valid manual URL check | *(GitHub Actions → Run workflow → `dry_run: true`)* Submit a real `https://` cybersecurity article URL. | The log shows the article extracted, triaged, and summarized without crashing or writing to the live database. |

---

### Part E: Mobile & Layout Check

| ID | Test Name | Steps to Follow | Expected Result (PASS) |
| :--- | :--- | :--- | :--- |
| **TC-20** | Mobile screen (375px wide) | Resize browser to phone width and scroll through the page. | No text overlaps, buttons stay on one clean line (horizontal scroll for filter bars is fine), and **Show deep dive** is easy to tap. |

---

## 5. What Is Already Tested Automatically vs. What YOU Check

You don't have to re-test everything by hand every single time!

| Tested Automatically (By GitHub CI on every code change) | Tested By Hand (Your focus as QA) |
| :--- | :--- |
| Blocking unsafe URLs, private IPs, and bad redirects | Reading 2–3 new English briefings to check if the translation from French sounds natural and accurate |
| Blocking bot-walls and articles under 150 words | Checking if two briefings on the screen are accidentally about the exact same story (missed merge) |
| Merging matching CVEs and keeping different CVEs apart | Checking visual look & spacing on Chrome, Safari, and mobile phone width |
| Escaping `<script>` text in web cards and HTML emails | Checking 1 real daily email in Gmail / Outlook / Apple Mail (making sure it doesn't look broken in dark mode or land in Spam) |
| Skipping Resend emails when the owner toggle is Off | Testing a brand-new feed URL when someone adds a new source to `config/feeds.json` |

---

## 6. How to Report a Bug (Copy & Paste Template)

When a test **FAILS**, create a GitHub Issue or message the developer using this template:

```markdown
**Bug Title:** [Short summary, e.g., "Two clear X buttons appear in search box on Safari"]
**Severity:** Critical / High / Medium / Low
**Where:** Live Website / Preview / Daily Email / GitHub Action
**Browser & Device:** e.g., Chrome 131 on macOS (Desktop) or Safari on iPhone

**Steps to Reproduce:**
1. Open the dashboard
2. Type "Nginx" in the search bar
3. Look at the right edge of the input

**Expected Result:**
Only one grey X button should appear.

**Actual Result:**
Both a grey X and a blue X appear next to each other.

**Evidence:**
- Attach screenshot or screen recording
- Copy any red error message from Browser Console or GitHub Action logs
```
