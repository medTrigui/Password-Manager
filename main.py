# Input/Output and Utility Imports
import base64
import binascii
import bcrypt
import keyboard as keyboard
import os
import psycopg2
import random
import string
import time
from datetime import datetime
from getpass import getpass

# Cryptography Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

conn = psycopg2.connect(host='localhost',
                        user='postgres',
                        password='2002',
                        dbname='PassManagProject',
                        )
cursor = conn.cursor()


def clear_screen():
    # Clear the screen based on the operating system
    if os.name == 'posix':  # Linux and macOS
        os.system('clear')
    elif os.name == 'nt':  # Windows
        os.system('cls')


def get_usernames():
    cursor.execute("SELECT username FROM users;")
    result = cursor.fetchall()
    usernames = [row[0] for row in result]
    return usernames


def get_emails():
    cursor.execute("SELECT email FROM users;")
    result = cursor.fetchall()
    emails = [row[0] for row in result]
    return emails


def generate_strong_password():
    """
    Criteria for the generate_password() function:

        *Length: The password has a random length between 8 and 12 characters.
        *Lowercase Letters: At least three lowercase letters (a-z) are included.
        *Uppercase Letters: At least one uppercase letter (A-Z) is included.
        *Digits: At least one digit (0-9) is included.
        *Special Characters: At least one special character (punctuation) is included.
        *Remaining Characters: The remaining characters, determined by the length of the password minus 5, are randomly
         selected from lowercase and uppercase letters, digits, and punctuation marks."""

    length = random.randint(8, 12)  # Random length between 8 and 12
    password = []

    password.append(random.choice(string.ascii_lowercase) * 3)  # Add three lowercase letters
    password.append(random.choice(string.ascii_uppercase))  # Add one uppercase letter
    password.append(random.choice(string.digits))  # Add one digit
    password.append(random.choice(string.punctuation))  # Add one special character

    remaining_length = length - 6
    password.extend(random.choices(string.ascii_letters + string.digits + string.punctuation, k=remaining_length))

    random.shuffle(password)

    generated_password = ''.join(password)
    return generated_password


def create_account():
    # prompt for a unique username
    while True:
        username = input("Enter a username: ")
        if username not in get_usernames():
            break
        else:
            print("The username you entered is already associated to an account. ")

    # prompt for email
    while True:
        email = input("Enter your email address: ")
        if email not in get_emails():
            break
        else:
            print("The email you entered is already associated to an account. ")

    clear_screen()

    # prompt for password
    while True:
        print('Please choose an option: \n'
              '            1. Generate strong random password for my account \n'
              '            2. Choose my own password ')

        ans = input("")
        clear_screen()
        if ans == '1' or ans == '2':
            break
        else:
            print("Invalid option. ")

    if ans == '1':
        password = generate_strong_password()
        print("Here's a strong password for your Password Manager account: " + password + "\n" "Please remember it!")

    elif ans == '2':
        print("Sure! Please make sure you choose a strong password for your account. ")
        max_attempts = 3
        attempt = 0
        while attempt < max_attempts:
            # prompt the user for Master password input
            print("Enter a password: ")
            password = getpass()
            clear_screen()
            print("Re-enter your password: ")
            check = getpass()

            # password mismatch
            if password != check:
                attempt += 1
                print('\nThe passwords do not match. Remaining attempts: ' + str(max_attempts - attempt))
                if attempt == 3:
                    print("You have exceeded the maximum number of attempts. Please try again later. ")
                    main()

            # password match
            if password == check:
                clear_screen()
                break

    # Generate a salt for password hashing
    salt = bcrypt.gensalt()
    #  the password using bcrypt
    pwd_hash = bcrypt.hashpw(password.encode("utf-8"), salt)

    # prompt for security question
    while True:
        print('''
                Please choose a security question:
                
                1. What is the name of your favorite childhood teacher?
                2. What was the first concert you attended?
                3. What is the name of the hospital where you were born?
                4. What is the model of your first car?
                5. In what city did you meet your spouse/partner?
                6. What is the name of your favorite sports team?
                7. What is the name of your favorite fictional character?
                8. What is your favorite dish or recipe?
                9. What is the name of the street you grew up on?
                10. What is the name of the first company you worked for? ''')
        selected = input("")
        if selected.isdigit() and (1 <= int(selected) <= 10):  # Valid input -> continue
            break
        else:
            print("Invalid input. "
                  "Please choose a number from 1 to 10 that corresponds to your preferred security question ")

    question_mapping = {
        "1": "What is the name of your favorite childhood teacher?",
        "2": "What was the first concert you attended?",
        "3": "What is the name of the hospital where you were born?",
        "4": "What is the model of your first car?",
        "5": "In what city did you meet your spouse/partner?",
        "6": "What is the name of your favorite sports team?",
        "7": "What is the name of your favorite fictional character?",
        "8": "What is your favorite dish or recipe?",
        "9": "What is the name of the street you grew up on?",
        "10": "What is the name of the first company you worked for?"
    }
    selected_security_question = question_mapping.get(selected)

    clear_screen()

    # security answer
    max_attempts = 3
    attempt = 0
    while attempt < max_attempts:
        # prompt for security answer
        security_answer = getpass("Please answer the security question you chose: ")
        clear_screen()
        security_answer_check = getpass("Re-enter your answer to confirm: ")

        # answer mismatch
        if security_answer != security_answer_check:
            attempt += 1
            print('\nThe answers do not match. Remaining attempts: ' + str(max_attempts - attempt))
            if attempt == 3:
                print("You have exceeded the maximum number of attempts. Please try again later. ")
                main()

        # answer match
        else:
            print("Your account has been created successfully! ")
            break

    # Generate a salt for security answer hashing
    salt = bcrypt.gensalt()
    #  the security answer using bcrypt
    sec_ans_hash = bcrypt.hashpw(security_answer.encode("utf-8"), salt)
    time.sleep(2)
    clear_screen()

    try:
        # Execute the SQL query to insert the security question
        cursor.execute(
            'INSERT INTO users (username, email, hashed_pwd, security_question, security_answer) VALUES (%s, %s, %s, '
            '%s, %s)',
            (username, email, pwd_hash, selected_security_question, sec_ans_hash))
        conn.commit()

        print("Your account has been successfully created!")
    except Exception as e:
        print("An error occurred while creating your account. Please try again later.")


def login():
    # Prompt user for username and password
    username = input("Enter your username: ")

    if username not in get_usernames():
        print("The username you entered isn’t connected to an account.")
        time.sleep(1.5)
        main()

    else:
        print("Enter your Master password: ")
        master_password = getpass()
        # Retrieve the stored hashed password in string format
        cursor.execute('SELECT hashed_pwd from users WHERE users.username = %s;', (username,))
        row = cursor.fetchone()
        stored_hash_str = row[0]

        # Clean the stored hash string
        cleaned_hash_str = stored_hash_str.replace('\\x', '').replace(' ', '').replace("'", '')

        try:
            # Convert the stored hashed password to binary format
            stored_hash_bytes = binascii.unhexlify(cleaned_hash_str)

            # Check the entered password against the stored hashed password
            if bcrypt.checkpw(master_password.encode('utf-8'), stored_hash_bytes):
                clear_screen()
                print(f'Welcome back {username}!')
            else:
                clear_screen()
                print('Password is incorrect.')
                time.sleep(1.5)
                main()

        except binascii.Error:
            return 'Invalid hash format'
    return username, master_password


def delete_account():
    clear_screen()
    print("Are you sure you want to delete your account from the password manager?")
    print("This action will permanently delete your account, along with all your stored passwords.")

    while True:
        ans = input()
        if ans == "yes" or ans == "no":
            clear_screen()
            break
        else:
            clear_screen()
            print("Invalid answer. Please enter 'yes' if you want to proceed with deleting your account, or 'no' if "
                  "you want to stop the deletion. ")

    if ans == 'yes':
        print("Enter your account email to continue: ")
        input_email = input("")
        if input_email in get_emails():
            print("Enter your master password")
            input_password = getpass()

            # Retrieve the stored hashed password in string format
            cursor.execute('SELECT hashed_pwd from users WHERE users.email = %s;', (input_email,))
            row = cursor.fetchone()
            stored_hash_str = row[0]

            # Clean the stored hash string
            cleaned_hash_str = stored_hash_str.replace('\\x', '').replace(' ', '').replace("'", '')

            try:
                # Convert the stored hashed password to binary format
                stored_hash_bytes = binascii.unhexlify(cleaned_hash_str)

                # Check the entered password against the stored hashed password
                if bcrypt.checkpw(input_password.encode('utf-8'), stored_hash_bytes):

                    clear_screen()
                    cursor.execute('DELETE from users WHERE users.email = %s;', (input_email,))
                    conn.commit()

                    print(
                        f"The account associated with the email address '{input_email}' has been successfully deleted.")
                    print("We apologize for any inconvenience caused.")
                    time.sleep(2)
                    main()
                else:
                    clear_screen()
                    print('Password is incorrect. Action failed.')
                    time.sleep(2)
                    main()
            except binascii.Error:
                return 'Invalid hash format'
    else:
        print("Great! Your account has not been deleted.")
        time.sleep(2)
        main()


def generate_encryption_key(master_password):
    # Derives an encryption key from the master password using a key derivation function (KDF).
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'',
        length=32,  # Desired key length in bytes (adjust according to your needs)
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode('utf-8'))
    return key


def encrypt_password(password, encryption_key):
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Create a cipher object with the encryption key, AES algorithm, and CBC mode
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())

    # Create a padder using PKCS7 padding scheme
    padder = padding.PKCS7(128).padder()

    # Pad the password
    padded_password = padder.update(password.encode('utf-8')) + padder.finalize()

    # Encrypt the password
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()

    # Combine the IV and encrypted password
    iv_and_encrypted_password = iv + encrypted_password

    # Encode the combined value as base64 for storage
    encoded_password = base64.urlsafe_b64encode(iv_and_encrypted_password).decode('utf-8')

    return encoded_password


def decrypt_password(encoded_password, encryption_key):
    # Decode the encoded password from base64
    iv_and_encrypted_password = base64.urlsafe_b64decode(encoded_password)

    # Extract the IV and encrypted password
    iv = iv_and_encrypted_password[:16]
    encrypted_password = iv_and_encrypted_password[16:]

    # Create a cipher object with the encryption key, AES algorithm, and CBC mode
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())

    # Create an unpadder using PKCS7 padding scheme
    unpadder = padding.PKCS7(128).unpadder()

    # Decrypt the password
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()

    # Unpad the decrypted password
    unpadded_password = unpadder.update(decrypted_password) + unpadder.finalize()

    # Return the decrypted password
    return unpadded_password.decode('utf-8')


def add_password(username, master_password):
    clear_screen()
    query = "SELECT website FROM passwords WHERE user_id = (SELECT user_id FROM users WHERE " \
            "username = %s)"
    cursor.execute(query, (username,))
    result = cursor.fetchall()
    websites = []
    for row in result:
        websites.append(row[0])

    try:
        website = input("Enter the website: ")
        if website not in websites:
            password = getpass("Enter the corresponding password: ")
            created_at = datetime.now()  # Get the current timestamp

            # Generate an encryption key from the master password
            encryption_key = generate_encryption_key(master_password)

            # Encrypt the password
            encoded_password = encrypt_password(password, encryption_key)

            query = "SELECT user_id FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            result = cursor.fetchall()
            user_id = int([row[0] for row in result][0])

            cursor.execute(
                'INSERT INTO passwords (user_id, website, password, created_at) VALUES (%s, %s, %s, %s)',
                (user_id, website, encoded_password, created_at))
            conn.commit()
            clear_screen()
            print("Password stored successfully!")
        else:
            print("The website already exists. Would you like to update the corresponding password? ")
            answer = input("(y) or (n): ")
            if answer == 'y':
                update_password(username, master_password)
            else:
                print("No problem. \n""Returning to main..")
                time.sleep(1)
                main()

    except (Exception, psycopg2.Error) as error:
        conn.rollback()  # Roll back the transaction if an exception occurs
        print(f"An error occurred: {str(error)}")
        print("Password creation failed.")
        time.sleep(3)
        main()


def view_passwords(username, master_password):
    clear_screen()

    query = "SELECT security_question, security_answer FROM users WHERE user_id = (SELECT user_id FROM users WHERE " \
            "username = %s)"
    cursor.execute(query, (username,))
    result = cursor.fetchall()
    for row in result:
        security_question = row[0]
        stored_hash_answer = row[1]

    print("To view your passwords, you must answer the security question first: ")
    print(security_question)
    answer = getpass("Answer: ")

    # Clean the stored hash string
    cleaned_hash_str = stored_hash_answer.replace('\\x', '').replace(' ', '').replace("'", '')

    try:
        # Convert the stored hashed answer to binary format
        stored_hash_bytes = binascii.unhexlify(cleaned_hash_str)

        # Check the entered answer against the stored hashed answer
        if bcrypt.checkpw(answer.encode('utf-8'), stored_hash_bytes):
            clear_screen()
            try:
                query = "SELECT website, password FROM passwords WHERE user_id = (SELECT user_id FROM users WHERE " \
                        "username = %s)"
                cursor.execute(query, (username,))
                result = cursor.fetchall()

                if len(result) == 0:
                    print("No passwords found.")
                else:
                    for row in result:
                        website = row[0]
                        encoded_password = row[1]

                        encryption_key = generate_encryption_key(master_password)

                        decrypted_password = decrypt_password(encoded_password, encryption_key)

                        print(f"Website: {website}")
                        print(f"Password: {decrypted_password}")
                        print("")
                time.sleep(3)

            except (Exception, psycopg2.Error) as error:
                print(f"An error occurred: {str(error)}")
                print("Failed to retrieve passwords.")

        else:
            clear_screen()
            print('Incorrect security answer.')
            time.sleep(1.5)
            main()

    except binascii.Error:
        return 'Invalid hash format'


def search(username, master_password):
    clear_screen()

    query = "SELECT security_question, security_answer FROM users WHERE user_id = (SELECT user_id FROM users WHERE " \
            "username = %s)"
    cursor.execute(query, (username,))
    result = cursor.fetchall()
    for row in result:
        security_question = row[0]
        stored_hash_answer = row[1]

    print("To view your password, you must answer the security question first: ")
    print(security_question)
    answer = getpass("Answer: ")

    # Clean the stored hash string
    cleaned_hash_str = stored_hash_answer.replace('\\x', '').replace(' ', '').replace("'", '')

    try:
        # Convert the stored hashed answer to binary format
        stored_hash_bytes = binascii.unhexlify(cleaned_hash_str)

        # Check the entered answer against the stored hashed answer
        if bcrypt.checkpw(answer.encode('utf-8'), stored_hash_bytes):
            clear_screen()
            try:
                website = input("Please enter the website for which you would like to check the password: ")
                query = "SELECT website, password FROM passwords WHERE user_id = (SELECT user_id FROM users WHERE " \
                        "username = %s) AND website = %s"
                cursor.execute(query, (username, website))
                result = cursor.fetchall()

                if len(result) == 0:
                    print("No passwords found for the requested website.")
                else:
                    for row in result:
                        website = row[0]
                        encoded_password = row[1]

                        encryption_key = generate_encryption_key(master_password)

                        decrypted_password = decrypt_password(encoded_password, encryption_key)

                        print(f"Website: {website}")
                        print(f"Password: {decrypted_password}")
                        print("")
                time.sleep(3)

            except (Exception, psycopg2.Error) as error:
                print(f"An error occurred: {str(error)}")
                print("Failed to retrieve passwords.")

        else:
            clear_screen()
            print('Incorrect security answer.')
            time.sleep(1.5)
            main()

    except binascii.Error:
        return 'Invalid hash format'


def update_password(username, master_password):
    clear_screen()
    query = "SELECT website FROM passwords WHERE user_id = (SELECT user_id FROM users WHERE " \
            "username = %s)"
    cursor.execute(query, (username,))
    result = cursor.fetchall()
    websites = []
    for row in result:
        websites.append(row[0])

    website = input("Enter the website for which you want to update the password: ")

    if website in websites:
        query = "SELECT security_question, security_answer FROM users WHERE user_id = (SELECT user_id FROM users WHERE"\
                "username = %s)"
        cursor.execute(query, (username,))
        result = cursor.fetchall()
        for row in result:
            security_question = row[0]
            stored_hash_answer = row[1]

        print("To update a password, you must answer the security question first: ")
        print(security_question)
        answer = getpass("Answer: ")

        # Clean the stored hash string
        cleaned_hash_str = stored_hash_answer.replace('\\x', '').replace(' ', '').replace("'", '')

        try:
            # Convert the stored hashed answer to binary format
            stored_hash_bytes = binascii.unhexlify(cleaned_hash_str)

            # Check the entered answer against the stored hashed answer
            if bcrypt.checkpw(answer.encode('utf-8'), stored_hash_bytes):
                clear_screen()

                max_attempts = 2
                attempt = 0
                while attempt < max_attempts:
                    new_password = getpass("Enter the new password: ")
                    clear_screen()
                    check_new_password = getpass("Re-enter the new password to confirm: ")

                    if new_password != check_new_password:
                        attempt += 1
                        print('\nThe passwords do not match. Remaining attempts: ' + str(max_attempts - attempt))
                        if attempt == 2:
                            print("You have exceeded the maximum number of attempts. Please try again later. ")
                            time.sleep(1.5)
                            main()
                    elif new_password == check_new_password:
                        clear_screen()
                        break

                encryption_key = generate_encryption_key(master_password)
                encrypted_password = encrypt_password(new_password, encryption_key)
                created_at = datetime.now()

                try:
                    query = "UPDATE passwords SET password = %s, created_at = %s WHERE user_id = (SELECT user_id FROM "\
                            "users WHERE " \
                            "username = %s) AND website = %s"
                    cursor.execute(query, (encrypted_password, created_at, username, website))
                    conn.commit()
                    print("Password updated successfully.")

                except (Exception, psycopg2.Error) as error:
                    conn.rollback()
                    print(f"An error occurred: {str(error)}")
                    print("Failed to update password.")

            else:
                clear_screen()
                print('Incorrect security answer.')
                time.sleep(1.5)
                main()
        except binascii.Error:
            return 'Invalid hash format'
    else:
        print("The website you entered does not exist in your account. Would you like to add it? ")
        answer = input("(y) or (n): ")
        if answer == 'y':
            add_password(username, master_password)
        else:
            print("No problem. \n""Returning to main..")
            time.sleep(1)
            main()


def delete_password(username):
    clear_screen()
    query = "SELECT website FROM passwords WHERE user_id = (SELECT user_id FROM users WHERE " \
            "username = %s)"
    cursor.execute(query, (username,))
    result = cursor.fetchall()
    websites = []
    for row in result:
        websites.append(row[0])

    website = input("Enter the website for which you want to delete the password: ")

    if website in websites:
        try:
            query = "SELECT security_question, security_answer FROM users WHERE user_id = (SELECT user_id FROM users " \
                    "WHERE " \
                    "username = %s)"
            cursor.execute(query, (username,))
            result = cursor.fetchall()
            for row in result:
                security_question = row[0]
                stored_hash_answer = row[1]

            print("To delete a password, you must answer the security question first: ")
            print(security_question)
            answer = getpass("Answer: ")

            # Clean the stored hash string
            cleaned_hash_str = stored_hash_answer.replace('\\x', '').replace(' ', '').replace("'", '')

            # Convert the stored hashed answer to binary format
            stored_hash_bytes = binascii.unhexlify(cleaned_hash_str)

            # Check the entered answer against the stored hashed answer
            if bcrypt.checkpw(answer.encode('utf-8'), stored_hash_bytes):
                query = "DELETE FROM passwords WHERE user_id = (SELECT user_id FROM users WHERE " \
                        "username = %s) AND website = %s"
                cursor.execute(query, (username, website))
                conn.commit()
                print("Password deleted successfully.")
            else:
                clear_screen()
                print('Incorrect security answer.')
                time.sleep(1.5)
                main()

        except (Exception, psycopg2.Error) as error:
            conn.rollback()
            print(f"An error occurred: {str(error)}")
            print("Failed to delete password.")
    else:
        print("The website you entered does not exist in your account.")
        time.sleep(1.5)
        main()


def password_generator(length=12, include_digits=True, include_symbols=True, include_uppercase=True):
    # Define character sets
    chars = string.ascii_lowercase
    if include_digits:
        chars += string.digits
    if include_symbols:
        chars += string.punctuation
    if include_uppercase:
        chars += string.ascii_uppercase

    # Generate password
    password = ''.join(random.choice(chars) for _ in range(int(length)))
    clear_screen()
    print("Here is a randomly-generated password based on the criteria you provided: {0}".format(password))
    time.sleep(2.5)
    return password


def main():
    while True:
        clear_screen()
        print('''
            Welcome to Your Password Manager!
    
            Please select an option:\n
                1. Sign-Up/Getting started
                2. Login page
                3. Help/Instructions
                4. Exit
        ''')
        ans = input("")

        if ans == '1':
            clear_screen()
            create_account()
        elif ans == '2':
            clear_screen()
            username, master_password = login()
            i = 0
            while True:
                i = i + 1
                if i != 1:
                    time.sleep(4)
                    clear_screen()
                print('''
                    Please select an option:\n
                        1. View Passwords
                        2. Add Password
                        3. Update Password
                        4. Delete password
                        5. Search
                        6. Password Generator
                        7. Account Settings
                        8. Help/Instructions
                        9. Exit
                ''')
                option = input("")

                if option == '1':
                    view_passwords(username, master_password)

                elif option == '2':
                    add_password(username, master_password)

                elif option == '3':
                    update_password(username, master_password)

                elif option == '4':
                    delete_password(username)

                elif option == '5':
                    search(username, master_password)

                elif option == '6':
                    clear_screen()
                    while True:
                        length = input("Enter the desired length for your random password: ")
                        if length.isdigit():
                            break
                        else:
                            print("Invalid length type. ")

                    while True:
                        print("Would you like to include digits in the password? ")
                        include_digits = True
                        answer_digits = input("(y) or (n): ")
                        if answer_digits == 'n':
                            include_digits = False
                            break
                        elif answer_digits == 'y':
                            break
                        else:
                            print("Invalid choice.")

                    while True:
                        print("Would you like to include Upper-case letters in the password? ")
                        include_upper = True
                        answer_upper = input("(y) or (n): ")
                        if answer_upper == 'n':
                            include_upper = False
                            break
                        elif answer_upper == 'y':
                            break
                        else:
                            print("Invalid choice.")

                    while True:
                        print("Would you like to include symbols in the password? ")
                        include_symbols = True
                        answer_symbols = input("(y) or (n): ")
                        if answer_symbols == 'n':
                            include_symbols = False
                            break
                        elif answer_symbols == 'y':
                            break
                        else:
                            print("Invalid choice.")

                    password_generator(length, include_digits, include_symbols, include_upper)

                elif option == '7':
                    clear_screen()
                    print('''
                        1. Change Master Password
                        2. Change Username
                        3. Change Account Email
                        4. Delete Account
                    ''')
                    choice = input("")
                    clear_screen()
                    if choice == '4':
                        delete_account()
                elif option == '8':
                    clear_screen()
                    print('''Help/Instructions:
    
                        Welcome to the Password Manager App!
    
                        Here's a quick guide to help you make the most of the app:
    
                        1. View Passwords:
                           See a list of all your saved passwords, along with the account names.
                        2. Add Password:
                           Store a new password securely by providing the account name, username, and password.
                        3. Update Password:
                           Modify an existing password entry. Choose the account and provide the updated details.
                        4. Delete Password:
                           Remove a password entry that you no longer need. Select the account to delete.
                        5. Search:
                           Quickly find a specific password by entering keywords or account names.
                        6. Password Generator:
                           Generate a strong and random password for your accounts. Customize the length and complexity.
                        7. Account Settings:
                           Manage your account preferences. Update your username, email address, master password.
                           Delete account
                        8. Help/Instructions:
                           Access this helpful guide anytime for instructions on using the app's features.
                        9. Exit:
                            Log out of the app and return to the login screen.
    
                        If you have any questions or need further assistance, don't hesitate to reach out to our support team.
                        Enjoy using the Password Manager App! 
                    ''')
                    print("Press 'q' to go back.")

                    while True:
                        if keyboard.is_pressed('q'):
                            break
                    clear_screen()
                elif option == '9':
                    main()
                else:
                    print("Invalid choice.")

        elif ans == '3':
            clear_screen()
            print("=== Password Manager Help/Instructions ===")
            print()
            print("To sign up and get started, select option 1 from the main menu." '\n')
            print("If you already have an account, choose option 2 to access the login page." '\n')
            print("If you wish to exit the password manager, choose option 4." '\n')
            print()
            print("Press 'q' to go back.")

            while True:
                if keyboard.is_pressed('q'):
                    break
            clear_screen()
            main()

        elif ans == '4':
            print("Goodbye!")
            exit()


if __name__ == "__main__":
    main()

