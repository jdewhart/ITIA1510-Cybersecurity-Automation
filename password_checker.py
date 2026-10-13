policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True }

def check_length(password, policy):
    #checks password, returns length_ok and length_verdict)
    password_length = len(password)
    length_ok = password_length >= policy["strong_length"]
    if password_length < policy["min_length"]:
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

def check_rotation(rotation_interval, policy):
    #checks rotation interval, returns rotation_ok, rotation_verdict
    rotation_ok = rotation_interval <= policy["max_rotation_months"]
    if rotation_interval > policy["max_rotation_months"]:
        rotation_verdict = "WARNING — rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= policy["good_rotation_months"]:
        rotation_verdict = "ACCEPTABLE — rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT — frequent rotation policy detected"
    return rotation_ok, rotation_verdict

def audit_password(account, username, password, rotation_interval, known_breached, policy, report_lines):
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    not_breached = check_breach(password, known_breached)

    overall_pass = length_ok and has_digit and not_username and not_breached

    report_lines.append('Account:  ' + account)
    report_lines.append('Username: ' + username)
    report_lines.append('Password length: ' + str(len(password)))
    report_lines.append('Length score: ' + str(len(password) * 10))
    report_lines.append('Rotation interval: ' + str(rotation_interval))
    report_lines.append('Rotations (3 yr): ' + str(36 // rotation_interval))
    report_lines.append('----------------------------------------------')
    report_lines.append('Length veridct:   ' + length_verdict)
    report_lines.append('Digit found:    ' + str(has_digit))
    report_lines.append('Username match: ' + str(not not_username))
    if not_breached == False:
        report_lines.append('Breach check: CRITICAL -- password found in known breach list')
    else:
        report_lines.append('Breach check: NOT CRITICAL -- password not found in known breach list')
    report_lines.append('Rotation verdict: ' + rotation_verdict)
    report_lines.append('----------------------------------------------')
    if overall_pass:
        report_lines.append('OVERALL:  PASS -- see findings above')
    else:
        report_lines.append('OVERALL:  FAIL -- see findings above')
    print('==============================================')

    
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

def load_breached(filepath):
    """Read the breached password file. Returns a list of password strings."""
    known_breached = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line != "":
                known_breached.append(line)
    return known_breached

def load_credentials(filepath):
    """Read the credentials file. Returns a list of credentials"""
    credentials = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue
            fields = line.split(",")
            credentials.append({"account": fields[0],
                                "username": fields[1],
                                "password": fields[2],
                                "rotation_interval": int(fields[3]), })
                   
    return credentials


def write_report(report_lines, filepath):
    """Write each string in report_lines to the file as one line."""
    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")


if __name__ == '__main__':
    # Uses statement above to ensure program does not automatically run when imported.
    # Batch processing
    count = 0
    summary = {"total": 0, "passed": 0, "failed": 0, "critical": 0,
               "failed_accounts": [], "critical_accounts": []}
    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")
    report_lines = []
 
    for cred in credentials:
        passed, failed, critical = audit_password(
            cred["account"], cred["username"], cred["password"],
            cred["rotation_interval"], known_breached, policy, report_lines)
        summary["total"] += 1
        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        if failed:
            summary["failed_accounts"].append(cred["account"])
        if critical:
            summary["critical_accounts"].append(cred["account"])

    report_lines.append('==============================================')
    report_lines.append('             BATCH AUDIT SUMMARY              ')
    report_lines.append('==============================================')
    report_lines.append('Credentials audited: ' + str(summary.get("total", 0)))
    report_lines.append('Passed:        ' + str(summary.get("passed", 0)))
    report_lines.append('Failed:        ' + str(summary.get("failed", 0)))
    report_lines.append('---------------------------------------------')
    report_lines.append('Failed accounts: ' + str(summary.get("failed_accounts", 0)))
    report_lines.append('Critical flags: ' + str(summary.get("critical", 0)))
    report_lines.append('Critical accounts: ' + str(summary.get("critical_accounts", 0)))
    report_lines.append('==============================================')
    for line in report_lines:
        print(line)
    write_report(report_lines, "report.txt")
   
