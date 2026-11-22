# 🖧 NetCut Dashboard (free)

**See every device on your Wi-Fi, and control its connection from a web page in your browser.**

Cut a device off the internet, slow it down, limit its speed to an exact number, watch which
sites it visits, redirect a website somewhere else — all from a clean dashboard, on **your own**
network.

![badge](https://img.shields.io/badge/platform-Windows-blue) ![badge](https://img.shields.io/badge/python-3.11%2B-green) ![badge](https://img.shields.io/badge/license-MIT-lightgrey)

---

## ⚠️ READ THIS FIRST — the rules

This tool sends **fake network messages** (ARP/NDP) and can **read traffic**. That is powerful,
and in most countries it is a **crime** to do it to a network or device you don't own.

✅ Allowed: your own home Wi-Fi, your own phone/PC/TV, a lab you control.
❌ Not allowed: your neighbour, a café, school/work Wi-Fi, anyone else's device.

**You** are responsible for how you use this. If in doubt — don't.

---

## 💡 What can it do?

| Feature | In plain words |
|---|---|
| **Scan** | Finds every phone, TV, console and laptop on your Wi-Fi and names them. |
| **Cut** | Takes a device off the internet completely. |
| **Weak Wi-Fi** | Makes a device laggy and slow instead of fully cutting it. |
| **Limit speed** | Gives a device an exact speed, e.g. "only 2 Mbps". |
| **Watch** | Shows which websites a device is opening, live (and keeps it online). |
| **Redirect** | Make a website open a different one (needs the extra HTTPS step). |
| **Protect** | Stops *other* people from cutting **you** off. |

---

## 🧰 What you need (about 10 minutes)

- A **Windows** PC connected to the Wi-Fi/router by **cable or Wi-Fi**.
- That's it. The steps below install the 3 free things it needs.

---

## 🚀 Install — step by step (for everyone)

> Do the steps **in order**. Don't skip Step 2 (Npcap) — nothing works without it.

### Step 1 — Install Python

1. Go to **https://www.python.org/downloads/** and click the big yellow **Download Python** button.
2. Open the file you downloaded.
3. ‼️ **VERY IMPORTANT:** at the bottom of the first window, tick the box
   **“Add python.exe to PATH”** before clicking Install. (If you forget this, the commands later
   won't work.)
4. Click **Install Now** and wait for it to finish.

### Step 2 — Install Npcap (the network driver)

1. Go to **https://npcap.com/#download** and download the **Npcap installer** (the `.exe`).
2. Open it and click **Next** through the screens.
3. ‼️ When you see a checkbox that says **“Install Npcap in WinPcap API-compatible Mode”**,
   **leave it ticked**.
4. Finish the install.

### Step 3 — Download this project

**Easy way (no git needed):**
1. At the top of this GitHub page click the green **`< > Code`** button → **Download ZIP**.
2. Find the ZIP in your Downloads, **right-click → Extract All**.
3. Remember where you put the folder (e.g. `C:\NetCut`).

### Step 4 — Install the two Python libraries

1. Press the **Windows key**, type **`powershell`**.
2. **Right-click “Windows PowerShell” → “Run as administrator”** → click **Yes**.
3. Copy–paste this line and press **Enter**:

   ```powershell
   pip install scapy cryptography
   ```

   Wait until it finishes (it downloads a bit).

### Step 5 — Run it (as Administrator)

Still in that **administrator** PowerShell window:

1. Go into the folder you extracted. If it's `C:\NetCut`, type:

   ```powershell
   cd C:\NetCut
   ```

   *(Change the path to wherever you put the folder.)*

2. Start the dashboard:

   ```powershell
   python netcut_gui.py
   ```

3. Your browser opens automatically at **http://127.0.0.1:8733**. 🎉
   (If it doesn't, open your browser and type that address yourself.)

> Must be **Administrator**, or cutting won't work. The window shows a red warning if you forgot.

---

## 🖱️ How to use the dashboard

1. Click **Scan** (top-right) — the cards fill with your devices.
2. On any device card:
   - **Cut** → takes it off the internet.
   - **Weak-WiFi ▾** → pick Light / Medium / Heavy to slow it down.
   - **Limit ▾** → type a download/upload speed in Mbps.
   - **👁 Watch ▾** → *Keep online* (just watch its traffic) or *Block + watch*.
3. Click **Resume** on a card (or **Resume all** at the top) to give it internet back.
4. Closing the window automatically un-cuts everyone.

---

## 📦 Optional: make a one-click `.exe`

Don't want to type commands every time? Build a single file you can double-click:

```powershell
python build_exe.py
```

This creates **`dist\NetCutDashboard.exe`**. Double-click it, click **Yes** on the Windows
admin pop-up, and the dashboard opens. (You still need Npcap installed, Step 2.)

---

## 🌐 Optional: DNS redirect & HTTPS (advanced)

Want `some-site.com` to open something else on a device? In the dashboard open **Redirects**,
tick **Intercept HTTPS**, then tap **Install CA on phone** and follow the on-screen steps to
trust the certificate on that device **once**. After that, redirects work on `https://` sites too.
This won't work on apps that use "certificate pinning" (most banking/chat apps) — only in a browser.

---

## 🩹 Troubleshooting

| Problem | Fix |
|---|---|
| `python` is not recognised | You missed **“Add to PATH”** in Step 1. Re-install Python and tick it. |
| Cutting does nothing | You're not **Administrator**. Close and reopen PowerShell with *Run as administrator*. |
| “Npcap” / scapy errors | Install **Npcap** (Step 2) with the *WinPcap-compatible* box ticked. |
| Device reconnects after a cut | On its card raise the attack **Level** to 3, or it auto-escalates. |
| A device stays online when cut | Remove any **Redirect** rule pointing at it (that auto-“watches” it), then Cut again. |
| Speed limit doesn't reach the exact number | On gigabit, use your **router's QoS**. Software shaping is best for low limits only. |

---

## ❓ FAQ

**Is this a virus?** No. It's open-source Python you can read. Antivirus may warn about the
built `.exe` only because it touches the network — that's expected for this kind of tool.

**Does it work on Mac/Linux?** It's built and tested for **Windows**. The engine is mostly
cross-platform, but the installer steps here are Windows-only.

**Will it slow my own PC?** No, the dashboard runs locally and only talks to `127.0.0.1`.

---

## 📜 License

**MIT** — free to use, change and share. See [LICENSE](LICENSE).
Bundles [`web/motion.js`](web/motion.js) — [Motion](https://motion.dev) (MIT).
