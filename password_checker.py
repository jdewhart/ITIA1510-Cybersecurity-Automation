# Batch processing
batch_size = 3
count = 0
total_pass = 0
total_fail = 0
critical_count = 0

while count < batch_size:
    # Gather input for this password analysis
    account = input("Enter the account name: ")
    username = input("Enter the username: ")
    password = input("Enter the password to analyze: ")
    rotation_interval = int(input("Enter the rotation interval (months): "))

    # Calculations
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    if password_length < 8:
        length_verdict = "WEAK — does not meet minimum length requirements"
    elif 8 <= password_length <= 11:
        length_verdict = "MODERATE — meets minimum but falls short of NIST recommendations"
    elif 12 <= password_length <= 14:
        length_verdict = "GOOD — acceptable length for most systems"
    else:
        length_verdict = "STRONG — meets NIST SP 800-63B recommendations"

    # Fixed Digit Check
    has_digit = False
    for char in password:
        if char in '0123456789':
            has_digit = True

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

    #Accumulate Batch Counters
    if overall_pass:
        total_pass = total_pass + 1
    else:
        total_fail = total_fail + 1
    
    if not not_username:
        critical_count = critical_count + 1

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
    count = count +  1

    # Critical warning if password == username
    if not not_username:
        print("CRITICAL — password must not match username.")

    # Overall verdict
    if overall_pass:
        print("\nOVERALL: PASS — password meets all checked criteria")
    else:
        print("\nOVERALL: FAIL — see findings above")

# batch summary printed after loop ends
print('=== BATCH SUMMARY ===')
print('Total audited: ' + str(batch_size))
print('Passed:        ' + str(total_pass))
print('Failed:        ' + str(total_fail))
print('Critical:      ' + str(critical_count))
print('NOTE: Input is still hardcoded -- file reading coming in Week 08.')
