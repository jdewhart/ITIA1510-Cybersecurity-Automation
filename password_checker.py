known_breached = ["password", "password123", "123456", "qwerty", "letmein", "welcome", "monkey", "dragon", "master", "sunshine"]

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

def audit_password(account, username, password, rotation_interval, known_breached):
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)
    not_breached = check_breach(password, known_breached)

    overall_pass = length_ok and has_digit and not_username and not_breached

    print('Account:  ' + account)
    print('Length veridct:   ' + length_verdict)
    print('Digit found:    ' + str(has_digit))
    print('Username match: ' + str(not not_username))
    print('Rotation verdict: ' + rotation_verdict)
    if overall_pass:
        print('OVERALL:  PASS')
    else:
        print('OVERALL:  FAIL')

    if not_breached == False:
        print('Breach check: CRITICAL -- password found in known breach list')
    else:
        print('Breach check: NOT CRITICAL -- password not found in known breach list')

    passed = 0
    failed = 0
    if overall_pass:
        passed = 1
    else:
        failed = 1

    critical = 0
    if not_username == False or not_breached == False:
        critical = 1

    return passed, failed, critical

def check_breach(password, known_breached):
    not_breached = password not in known_breached
    return not_breached
    
if __name__ == '__main__':
    # Uses statement above to ensure program does not automatically run when imported.
    # Batch processing
    count = 0
    total_pass = 0
    total_fail = 0
    critical_count = 0

    credentials = [
    ["Gmail", "jsmith", "password123", 12],
    ["SSH Server", "jsmith", "jsmith", 24],
    ["VPN", "jsmith", "Tr0ub4dor&3correct", 3],
    ["Company Email", "jsmith", "summer2024!", 6],
    ["GitHub", "jsmith", "Blue-Harbor-72-Lantern", 6],
    ]

    failed_accounts = []
    critical_accounts = []

    for record in credentials:
        account = record[0]
        username = record[1]
        password = record[2]
        rotation_interval = record[3]

        passed, failed, critical = audit_password(account, username, password, rotation_interval, known_breached)
        total_pass = total_pass + passed
        total_fail = total_fail + failed
        critical_count = critical_count + critical
        if failed:
             failed_accounts.append(account)
        if critical:
             critical_accounts.append(account)

    print('=== BATCH SUMMARY ===')
    print('Total audited: ' + str(len(credentials)))
    print('Passed:        ' + str(total_pass))
    print('Failed:        ' + str(total_fail))
    print('Critical:      ' + str(critical_count))
    print('-----------------------')
    print('Failed accounts: ' + str(failed_accounts))
    print('Critical accounts: ' + str(critical_accounts))
    print('-----------------------')
    print('NOTE: Breach list and credentials are hardcoded -- file reading coming in Week 08.')
