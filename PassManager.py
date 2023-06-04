import logging
import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog, ttk
from functools import partial

from PassGenerator import PassGenV2

#Database
with sqlite3.connect('sqdatabase.db') as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
platform TEXT NOT NULL,
account TEXT NOT NULL,
password TEXT NOT NULL);
""")

# Create Popup
def popup(text):
    answer = simpledialog.askstring("New Entry", text)

    return answer


# Initiate Window
window = Tk()

window.title("Password Manager by Alex")
window.iconbitmap("icons/icon.ICO")

# Hashing the password
def HashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash

# Screen for the first opening of the application - Add a master password
def FirstScreen():
    window.geometry('300x150')                                           #Window size

    lbl = Label(window, text="Create a Master Password")                 #First label
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")                              #First text box - master password creation
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text='Re-enter Password')                       #Second label
    lbl1.pack()

    txt1 = Entry(window, width=20, show='*')                             #Second text box - confirm new master password
    txt1.pack()

    

    #Saving the new master password to the database
    def SavePassword(*args):
        if txt.get() == txt1.get():                                      #Check if the password is typed correctly in both textboxes
            hashedPassword = HashPassword(txt.get().encode('utf-8'))     #Adds the new hashed master password into the database

            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?)"""
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()

            PasswordVault()
        else:
            txt.delete(0, 'end')
            txt1.delete(0, 'end')
            pwerror.config(text='The passwords do not match.')

    
    pwerror = Label(window, text='')                                     #Error in case the password is not typed correctly in both textboxes
    pwerror.pack()

    button = Button(window, text='Save', command=SavePassword)           #The submit button
    button.pack(pady=10)

    window.bind("<Return>", SavePassword)


#Login Screen if there is already a master password in the database
def LoginScreen():
    window.geometry("250x100")                                           #Window size

    lbl = Label(window, text="Enter the Master Password")                       
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=10, show='*')
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()

    #This function get's the master password and encodes it
    def GetMasterPassword():
        checkHashedPassword = HashPassword(txt.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        return cursor.fetchall()

    #Checks if the master password is correct or incorrect
    def CheckPassword(*args):
        match = GetMasterPassword()

        if match:
            PasswordVault()
        else:
            txt.delete(0, 'end')
            logging.error('The entered password was wrong.')
            lbl1.config(text='Wrong Password')

    button = Button(window, text='Submit', command=CheckPassword)
    button.pack(pady=10)
    window.bind("<Return>", CheckPassword)

#The main password vault where we will store all our data regarding password
def PasswordVault():
    for widget in window.winfo_children():
        widget.destroy()
    
    def addEntry():
        text1 = 'Platform'
        text2 = 'Account'
        text3 = 'Password'

        platform = popup(text1)
        account = popup(text2)
        password = popup(text3)

        insert_fields = """INSERT INTO vault(platform,account,password)
        VALUES(?,?,?)
        """

        cursor.execute(insert_fields, (platform,account,password))
        db.commit()
        PasswordVault()

    def updateEntry(input):
        update = "Type new password"
        password = popup(update)

        cursor.execute("UPDATE vault SET password = ? WHERE id = >", (password, input,))
        db.commit()
        PasswordVault()

    def removeEntry(input):
        cursor.execute('DELETE FROM vault WHERE id = ?', (input,))
        db.commit()
        PasswordVault()

    def copyAcc(input):
        window.clipboard_clear()
        window.clipboard_append(input)

    def copyPass(input):
        window.clipboard_clear()
        window.clipboard_append(input)

    # Window Layout and Design
    window.geometry('750x350')
    main_frame = Frame(window)
    main_frame.pack(fill=BOTH, expand=1)

    canvas = Canvas(main_frame)
    canvas.pack(side=LEFT, fill=BOTH, expand=1)

    scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=canvas.yview)
    scrollbar.pack(side=RIGHT, fill=Y)

    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    second_frame = Frame(canvas)

    canvas.create_window((0,0), window=second_frame, anchor="nw")

    lbl5 = Label(second_frame, text="Password Vault")
    lbl5.grid(column=2)

    genpassbtn = Button(second_frame, text="Generate Password", command=PassGenV2)
    genpassbtn.grid(column=1, pady=10)

    newpassbtn = Button(second_frame, text="Store New", command=addEntry)
    newpassbtn.grid(column=2,row=1, pady=10, padx=5)

    lbl6 = Label(second_frame, text="Platform")
    lbl6.grid(row=2, column=0, padx=40)
    lbl7 = Label(second_frame, text="Account")
    lbl7.grid(row=2, column=1, padx=40)
    lbl8 = Label(second_frame, text="Password")
    lbl8.grid(row=2, column=2, padx=40)


    cursor.execute('SELECT * FROM vault')
    if(cursor.fetchall() != None):
        i=0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()

            lbl1 = Label(second_frame, text=(array[i][1]), font=('Helvetica', 12))
            lbl1.grid(column=0, row=i+3)
            lbl1 = Label(second_frame, text=(array[i][2]), font=('Helvetica', 12))
            lbl1.grid(column=1, row=i+3)
            lbl1 = Label(second_frame, text=(array[i][3]), font=('Helvetica', 12))
            lbl1.grid(column=2, row=i+3)

            btn2 = Button(second_frame, text="Copy Acc", command=partial(copyAcc, array[i][2]))
            btn2.grid(column=3, row=i + 3, pady=10)
            btn3 = Button(second_frame, text="Copy Pass", command=partial(copyPass, array[i][3]))
            btn3.grid(column=4, row=i + 3, pady=10)
            btn1 = Button(second_frame, text="Update", command=partial(updateEntry, array[i][0]))
            btn1.grid(column=5, row=i + 3, pady=10)
            btn = Button(second_frame, text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=6, row=i + 3, pady=10)

            i += 1
            cursor.execute("SELECT * FROM vault")
            if(len(cursor.fetchall()) <= i):
                break

            

cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    LoginScreen()
else:
    FirstScreen()
window.mainloop()