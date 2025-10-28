# 🏦 Python SQL Banking App

A simple console-based banking system built with Python and SQLite, designed to showcase secure data handling, database integration, and clean code structure.  
It allows users to create accounts, deposit or withdraw money, transfer funds, and view transaction history — all with secure password hashing and CSV transaction logging.

---

## 🚀 Features

- 🔐 **Secure 4-digit PIN hashing (SHA-256)** — no plaintext PINs stored  
- 🧾 **Checking and Savings accounts** with deposits, withdrawals, and balance updates  
- 🧠 **Basic statistics** — view average balances and users above the average  
- 📝 **CSV transaction audit logging** for transparent tracking  
- 👤 **Interactive account creation and deletion** via the console menu  
- 🧪 **Three preloaded test accounts** for instant use:  
  - `alice` / **Password:** `P@ssw0rd1`  
  - `bob` / **Password:** `S3cr3t!2`  
  - `carla` / **Password:** `MyP@ss3`  

---

## 🧰 Tech Stack

- **Language:** Python 3  
- **Database:** SQLite (`bank.db` created automatically)  
- **Audit Logging:** CSV (`transactions.csv` auto-generated)  
- **No external libraries** — runs out of the box using only the Python standard library  

---

## ✍🏿 How to Run

```bash
git clone https://github.com/Bloccboi/My-Capstone-Project.git
cd Banking-app-capstone
python main.py
