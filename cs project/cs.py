import re
import pyautogui
import time

def generate_username_combinations(email):
    # Extracting username from email using regular expression
    match = re.match(r'(.)@.', email)
    if match:
        username = match.group(1)
        combinations = []

        # Adding username as it is
        combinations.append(username)

        # Adding numeric combinations
        combinations.append(username + "123")
        combinations.append("123" + username)

        # Adding username with "@" sign and numeric combination
        combinations.append(username + "@123")

        return combinations
    else:
        return []

# Example usage
email = input("Enter your email address: ")
username_combinations = generate_username_combinations(email)

# Automating the input process
for combination in username_combinations:
    time.sleep(5)  # Adding a small delay for smoother automation
    pyautogui.typewrite(combination)  # Type the combination
    time.sleep(1)
    pyautogui.press('enter')  # Press Enter
    time.sleep(1)
    pyautogui.press('enter')  # Press Enter
    time.sleep(1)