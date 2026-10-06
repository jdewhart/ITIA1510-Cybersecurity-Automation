from password_checker import check_length, check_digit, check_username, check_rotation, check_breach, known_breached, policy

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
