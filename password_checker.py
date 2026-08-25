
# Gather user input
account = input("Enter the account name: ")
username = input("Enter the username: ")
password = input("Enter the password to analyze: ")
rotation_interval = int(input("Enter the rotation interval (months): "))

#Calculations
password_length = len(password)
length_score = password_length * 10
rotation_count = 36 // rotation_interval

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

print("----------------------------------------")
print("NOTE: Classification requires conditionals -- coming in Week 02.")
print("========================================")
