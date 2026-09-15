def check_length(password):
    #checks password, returns length_ok and length_verdict)
    password_length = len(password)
    length_ok = password_length >= 15
    if password_length < 8:
                length_verdict = "WEAK -- does not meet minimum length requirements"
    elif 8 <= password_length <= 11:
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
    elif 12 <= password_length <= 14:
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"
    return length_ok, length_verdict

def check_digit(password):
    #check if password has a digit, returns has_digit
    has_digit = False
    for char in password:
        if char in '0123456789':
            has_digit = True
    return has_digit

def check_username(password, username):
    # Returns True when the password and username are different.
    not_username = password != username
    return not_username

def check_rotation(rotation_interval):
    #checks rotation interval, returns rotation_ok, rotation_verdict
    rotation_ok = rotation_interval <= 12
    if rotation_interval > 12:
        rotation_verdict = "WARNING — rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE — rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT — frequent rotation policy detected"
    return rotation_ok, rotation_verdict

def audit_password(account, username, password, rotation_interval):
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)

    overall_pass = length_ok and has_digit and not_username and rotation_ok

    print('ACCOUNT:  ' + account)
    print('LENGTH:   ' + length_verdict)
    print('DIGIT:    ' + str(has_digit))
    print('USERNAME: ' + str(not not_username))
    print('ROTATION: ' + rotation_verdict)
    if overall_pass:
        print('OVERALL:  PASS')
    else:
        print('OVERALL:  FAIL')

    passed = 0
    failed = 0
    if overall_pass:
        passed = 1
    else:
        failed = 1

    critical = 0
    if not_username == False:
        critical = 1

    return passed, failed, critical

if __name__ == '__main__':
    # Uses statement above to ensure program does not automatically run when imported.
    # Batch processing
    batch_size = 3
    count = 0
    total_pass = 0
    total_fail = 0
    critical_count = 0
    while count < batch_size:
        # Gather input for this password analysis
        count = count + 1
        account = input("Enter the account name: ")
        username = input("Enter the username: ")
        password = input("Enter the password to analyze: ")
        rotation_interval = int(input("Enter the rotation interval (months): "))
        passed, failed, critical = audit_password(account, username, password, rotation_interval)
        total_pass = total_pass + passed
        total_fail = total_fail + failed
        critical_count = critical_count + critical

    print('=== BATCH SUMMARY ===')
    print('Total audited: ' + str(batch_size))
    print('Passed:        ' + str(total_pass))
    print('Failed:        ' + str(total_fail))
    print('Critical:      ' + str(critical_count))
    print('NOTE: Input is still hardcoded -- file reading coming in Week 08.')
