from password_checker import(check_length, check_digit, check_username, check_rotation, check_breach, policy, load_credentials, load_breached, write_report)
known_breached = load_breached("breached.txt")

# check_length tests
length_ok, verdict = check_length('Pwd1', policy)
assert length_ok == False
print('PASS: check_length correctly identified weak password (length_ok = False)')

length_ok, verdict = check_length('ALongP@ssword2024!', policy)
assert length_ok == True
print('PASS: check_length correctly identified strong password (length_ok = True)')

# check_digit tests
assert check_digit('nodigitshere') == False
print('PASS: check_digit correctly returned False for password with no digits')
assert check_digit('P@ssw0rd!') == True
print('PASS: check_digit correctly returned True for password containing a digit')

# check_username tests
assert check_username('jsmith', 'jsmith') == False
print('PASS: check_username correctly returned False when password matches username')
assert check_username('P@ssw0rd!', 'jsmith') == True
print('PASS: check_username correctly returned True when password differs from username')

# check_rotation tests
rotation_ok, verdict = check_rotation(18, policy)
assert rotation_ok == False
print('PASS: check_rotation correctly returned False for 18-month interval')
rotation_ok, verdict = check_rotation(6, policy)
assert rotation_ok == True
print('PASS: check_rotation correctly returned True for 6-month interval')

# check_breach tests
assert check_breach("password123", known_breached) == False
print('PASS: check_breach correctly returned False when password is in known_breached')
assert check_breach("Tr0ub4dor&3correct", known_breached) == True
print('PASS: check_breach correctly returned True when password is not in known_breached')

# policy tests
assert policy ["strong_length"] == 15
print('PASS: policy correctly returned True when strong length == 15')
assert "require_digit" in policy
print('PASS: policy correctly returned True when require_digit is in policy')
print('All tests passed.')

# load_credentials tests
credentials = load_credentials("credentials.txt")
assert isinstance(credentials, list)
print('PASS: credentials returns a list')
assert "account" in credentials[0]
print('PASS: the first record has an account key')

# load_breached
assert isinstance(known_breached, list)
print('PASS: known_breached returns a list')
assert "password123" in known_breached
print('PASS: password 123 is in known_breached')

# write_report tests
test_strings = ["This is a test", "Test 2"]
write_report(test_strings, "test_report.txt")

with open("test_report.txt", "r") as f:
    content = f.read()

assert content == "This is a test\nTest 2\n"
print('PASS: text matches')
