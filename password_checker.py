
# Gather user input
account = input("Enter the account name: ")
username = input("Enter the username: ")
password = input("Enter the password to analyze: ")
rotation_interval = int(input("Enter the rotation interval (months): "))

#Calculations
password_length = len(password)
length_score = password_length * 10
rotation_count = 36 // rotation_interval

# Classify password strength based on length
if password_length < 8:
    length_verdict = "WEAK — does not meet minimum length requirements"
elif password_length > 8 and <= 11:
    length_verdict = "MODERATE — meets minimum but falls short of NIST recommendations"
elif password_length > 12 and <= 14:
    length_verdict = "GOOD — acceptable length for most systems"
else:
    length_verdict = "STRONG — meets NIST SP 800-63B recommendations"

# Check if password contains at least one digit using chained OR
has_digit = ('0' in password or '1' in password or '2' in password or
             '3' in password or '4' in password or '5' in password or
             '6' in password or '7' in password or '8' in password or
             '9' in password)

# USERNAME-AS-PASSWORD CHECK
not_username = password != username

# ROTATION FREQUENCY CHECK
# Classify rotation interval in months
if rotation_interval > 12:
    rotation_verdict = "WARNING — rotation interval exceeds recommended maximum of 12 months"
elif rotation_interval >= 6:
    rotation_verdict = "ACCEPTABLE — rotation interval within recommended range"
else:
    rotation_verdict = "EXCELLENT — frequent rotation policy detected"

# OVERALL VERDICT
length_ok = password_length >= 15
overall_pass = length_ok and has_digit and not_username

# Output
print("========================================")
print("        PASSWORD ANALYSIS REPORT        ")
print("========================================")

print("Account:          " , account)
print("Username:         " , username)
print("Password Length:   ", password_length)
print("Length Score:      ", length_score)
print("Rotation Interval:   ", rotation_interval,  "months")
print("Rotation Count:   "  , rotation_count)
print("------------------------")
print("Length Classification:   ", length_verdict)
print("Contains Digit:   ", has_digit)
print("Rotation Frequency:   ", rotation_verdict)
print("Password Matches Username:   ", not_username)

# Critical warning if password == username
if not not_username:
    print("CRITICAL — password must not match username.")

# Overall verdict
if overall_pass:
    print("\nOVERALL: PASS — password meets all checked criteria")
else:
    print("\nOVERALL: FAIL — see findings above")
