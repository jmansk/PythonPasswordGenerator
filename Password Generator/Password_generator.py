import random
import tkinter as tk
import pyperclip

# define a function to generate a password
def generate_password(length, uppercase, lowercase, digits, symbols):
    # create a list of possible characters based on user criteria
    possible_chars = ""
    if uppercase:
        possible_chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if lowercase:
        possible_chars += "abcdefghijklmnopqrstuvwxyz"
    if digits:
        possible_chars += "0123456789"
    if symbols:
        possible_chars += "!@#$%^&*()_-+={}[]|\:;'<>,.?/"
    
    # generate the password by selecting random characters from the possible characters list
    password = ""
    for i in range(length):
        password += random.choice(possible_chars)
    
    return password

# define a function to copy the password to the clipboard
def copy_to_clipboard(password):
    pyperclip.copy(password)

# create the UI
root = tk.Tk()
root.geometry("300x250+100+100")
root.title("Password Generator")

# create input fields for password criteria
length_label = tk.Label(root, text="Password Length:")
length_entry = tk.Entry(root)
length_label.pack()
length_entry.pack()

uppercase_var = tk.BooleanVar()
uppercase_var.set(True)
uppercase_checkbox = tk.Checkbutton(root, text="Include Uppercase Letters", variable=uppercase_var)
uppercase_checkbox.pack()

lowercase_var = tk.BooleanVar()
lowercase_var.set(True)
lowercase_checkbox = tk.Checkbutton(root, text="Include Lowercase Letters", variable=lowercase_var)
lowercase_checkbox.pack()

digits_var = tk.BooleanVar()
digits_var.set(True)
digits_checkbox = tk.Checkbutton(root, text="Include Digits", variable=digits_var)
digits_checkbox.pack()

symbols_var = tk.BooleanVar()
symbols_var.set(True)
symbols_checkbox = tk.Checkbutton(root, text="Include Symbols", variable=symbols_var)
symbols_checkbox.pack()

# create a button to generate the password
def generate_button_click():
    length = int(length_entry.get())
    uppercase = uppercase_var.get()
    lowercase = lowercase_var.get()
    digits = digits_var.get()
    symbols = symbols_var.get()
    
    password = generate_password(length, uppercase, lowercase, digits, symbols)
    
    password_label.config(text="Your Password is: " + password)
    
    # enable the "Copy to Clipboard" button
    copy_button.config(state="normal")
    
    # save the password to a variable for copying to the clipboard
    global password_to_copy
    password_to_copy = password

generate_button = tk.Button(root, text="Generate Password", command=generate_button_click)
generate_button.pack()

# create a button to copy the password to the clipboard
def copy_button_click():
    copy_to_clipboard(password_to_copy)

copy_button = tk.Button(root, text="Copy to Clipboard", state="disabled", command=copy_button_click)
copy_button.pack()

# create a label to display the generated password
password_label = tk.Label(root, text="")
password_label.pack()

# run the UI loop
root.mainloop()
