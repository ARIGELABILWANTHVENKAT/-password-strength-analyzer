import re
import math
import bcrypt
import sqlite3
import random
import string

# -----------------------------
# DATABASE SETUP
# -----------------------------
conn = sqlite3.connect("passwords.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS history (
    hash TEXT
)
""")
conn.commit()

# -----------------------------
# COMMON PASSWORD LIST
# -----------------------------
COMMON_PASSWORDS = {
    "123456","password","qwerty","admin",
    "letmein","welcome","iloveyou"
}

# -----------------------------
# ENTROPY CALCULATION
# -----------------------------
def calculate_entropy(password):
    pool = 0

    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"\d", password): pool += 10
    if re.search(r"[!@#$%^&*()_+=\-{}\[\]:;\"'<>,.?/]", password): pool += 32

    if pool == 0:
        return 0

    return round(len(password) * math.log2(pool), 2)

# -----------------------------
# PASSWORD EVALUATION
# -----------------------------
def evaluate_password(password):
    feedback = []
    score = 0

    # Length
    if len(password) >= 12:
        score += 2
    else:
        feedback.append("Use at least 12 characters.")

    # Character checks
    checks = [
        (r"[A-Z]", "Add uppercase letters."),
        (r"[a-z]", "Add lowercase letters."),
        (r"\d", "Add numbers."),
        (r"[!@#$%^&*()_+=\-{}\[\]:;\"'<>,.?/]", "Add special characters.")
    ]

    for pattern, msg in checks:
        if re.search(pattern, password):
            score += 1
        else:
            feedback.append(msg)

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("Avoid common passwords.")
    else:
        score += 2

    # Repetition check
    if re.search(r"(.)\1\1", password):
        feedback.append("Avoid repeated characters (aaa,111).")
    else:
        score += 1

    # Entropy rating
    entropy = calculate_entropy(password)

    if entropy > 60:
        rating = "Strong 💪"
    elif entropy > 40:
        rating = "Moderate ⚠️"
    else:
        rating = "Weak ❌"

    return rating, entropy, feedback

# -----------------------------
# PASSWORD REUSE CHECK
# -----------------------------
def is_reused(password):
    cursor.execute("SELECT hash FROM history")
    for (stored_hash,) in cursor.fetchall():
        if bcrypt.checkpw(password.encode(), stored_hash.encode()):
            return True
    return False

# -----------------------------
# STORE PASSWORD
# -----------------------------
def store_password(password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cursor.execute("INSERT INTO history VALUES (?)", (hashed.decode(),))
    conn.commit()

# -----------------------------
# STRONG PASSWORD GENERATOR
# -----------------------------
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

# -----------------------------
# MAIN PROGRAM (CLI)
# -----------------------------
def main():
    print("\n🔐 Password Strength Analyzer")
    print("----------------------------")

    while True:
        print("\n1. Check Password")
        print("2. Generate Strong Password")
        print("3. Exit")

        choice = input("\nChoose option: ")

        if choice == "1":
            pwd = input("\nEnter password: ")

            if is_reused(pwd):
                print("\n❌ Password already used before!")
                continue

            rating, entropy, tips = evaluate_password(pwd)

            print(f"\nStrength: {rating}")
            print(f"Entropy: {entropy} bits")

            if tips:
                print("\nSuggestions:")
                for tip in tips:
                    print("-", tip)

            if "Weak" in rating or "Moderate" in rating:
                print("\nSuggested strong password:")
                print(generate_password())

            store_password(pwd)

        elif choice == "2":
            print("\nGenerated Password:")
            print(generate_password())

        elif choice == "3":
            print("\nGoodbye 👋")
            break

        else:
            print("Invalid choice.")

    conn.close()

# Run program
main()
