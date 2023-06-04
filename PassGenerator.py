from msilib.schema import CheckBox
from random import randint
from tkinter import *


def PassGenV2():
    # Window
    root = Tk()
    root.title("Password Generator")

    myPassword = chr(randint(33,126))

    def newRand():
        pwEntry.delete(0, END)
        pwLength = int(myEntry.get())

        myPass = ''

        for x in range(pwLength):
            myPass += chr(randint(33,126))
        
        pwEntry.insert(0, myPass)

    def clipper():
        root.clipboard_clear()
        root.clipboard_append(pwEntry.get())
    
    # Label Frame
    lf = LabelFrame(root, text="How many characters?")
    lf.pack(pady=20)

    # Create Entry Box for number of Characters.
    myEntry = Entry(lf, font=("Helvetica", 12))
    myEntry.pack(pady=20, padx=20)

    # Create Entry Box for returned password
    pwEntry = Entry(root, text="", font=("Helvetica", 12), bd=0, bg="systembuttonface")
    pwEntry.pack(pady=20)

    # Frame for buttons
    myFrame = Frame(root)
    myFrame.pack(pady=20)

    allowspchar = Checkbutton(lf, text='Allow special characters')
    allowspchar.pack()

    # Create Buttons
    button = Button(myFrame, text='Generate Password', command=newRand)
    button.grid(row=0, column=0,padx=10)

    clipbtn = Button(myFrame, text="Copy to Clipboard", command= clipper)
    clipbtn.grid(row=0, column=1, padx=10)

    root.mainloop()