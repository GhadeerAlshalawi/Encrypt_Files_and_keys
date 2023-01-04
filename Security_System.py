from tkinter import *
from tkinter import messagebox
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import os
import struct
import bcrypt
import rsa

root=Tk()
#----------------------------
#(passive) the lable will print for the user in the screen
#when we create a lable as an input we use the object of TK() which is 'root' 
#also our text which will be appear for the user 
#and lastly the font we will give it as an input (font name, font size)
#----------------------------
#(active) the entry will help the user to enter some texts.
#when we create an entry as an input we use the object of TK() which is 'root'
#as well as the bd that's represent the size of the border 
#and the font, the font size will be the input for it
#sometimes we use show for the password to hide what the user wrote
#show means how will the text appears while the user entring the text.
#we used the asterisk(*) as an input to the show to make user test shows as a (***********)
#----------------------------
#the user has to click the button to run the command which is one of the methods
#when we create the button as an input we use the object of TK() which is 'root'
#also our text which will be appear for the user
#and the command we have to give it a specific method to run it
#and the height with the width to modify the size of the button
#as well as the bd that's represent the size of the border
#----------------------------
#we will use function peck() to make all of them appear in the screen
#and also function place() to modify thier position by using y axis and x axis (coordinate system)
#----------------------------

def dst():#this method clear the whole window (by destroying every single item on it)
    for item in root.winfo_children():#take each item in this root
        item.destroy()#destroy it

def all():
    dst()#destroy everything in the last page 
    root.title("Security system")#changing the title of the window
    root.geometry("600x450")#changing the size of the window

    def operations(Username): 
        root.title("Operations")#changing the title of the window
        root.geometry("600x450")#changing the size of the window
        name = Username #save the input for this method in new variable to use it when we want to call the same method >> operations(name)  

        def find_keys():#button Find keys will call this method
            #this method will find the public key of the users
            root.title("Find keys")#changing the title of the window
            root.geometry("600x450")#changing the size of the window
            dst()#dstroy everything in the last page 

            def back():#button Back will call this method
                operations(name)#calling method operations() to go back to operations page
            def Find():#button Find will call this method
                
                db = open("database.txt", "r")#open the file database that saves all the users data for reading
                Usernames = []#create a new array to save all the usernames on it
                PublicKeys = []#create a new array to save all the publickeys on it
                for i in db:#in each line in this file
                    a,b,y,z = i.split(",")#The split() function returns the strings as a list that separted by comma
                    y = y.strip()#the strip() method is to remove the whitespace from the beginning and at the end of the string
                    #The append() method in python adds an item to the existing list.
                    Usernames.append(a)#add the username in usernames list
                    PublicKeys.append(y)#add the public key un publickeys list
                    #zip() function that will aggregate elements from two or more
                    #dict() Dictionaries are used to store data values in key:value pairs.
                    data = dict(zip(Usernames, PublicKeys))

                if entry_Username.get() != "":#if user input in the username entery was not empty
                    if entry_Username.get() in data:#if user input in the username entery in the in the data variable
                        key = data[entry_Username.get()].strip('b')#in the 'data' list with same input in the username entery the second element will be returned which is the public key
                        dst()#dstroy evrything in the last page 

                        #----------------------------------------
                        # Here is the page that shows the user the output of the searching for the user's public key
                        #----------------------------------------

                        label_key=Label(root, text="Reciver/Sender public key : " + key ,font=("Arial", 10))#label that displays the requested key
                        label_key.pack()
                        label_key.place(x=160, y=190)
            
                        button_Find=Button(root, text="Back to Find",command=find_keys ,height=2, width=20, bd=3)#button to go back to find key page
                        button_Find.pack()
                        button_Find.place(x=160,y=300)
            
                        button_back=Button(root , command=back, text="Back to Operations", height=2, width=20, bd=3)#button to go back to operations page
                        button_back.pack()
                        button_back.place(x= 320, y=300)

                    else:#if user input in the username entery was not in the database
                        messagebox.showerror("","There is no username like that")#show an error that there is no username like that
                        find_keys()#calling the method again to clear the entries
                else:#if user input in the username entery was empty
                    messagebox.showerror("","Blank Not Allowed")#show an error that blank not allowed

            #----------------------------------------
            # Here is the page that helps the user to find user's public key
            #----------------------------------------    
                
            label_Username=Label(root, text="Enter reciver/sender Username : ",font=("Arial", 10))#displays the what will be written in the entry_Username
            label_Username.pack()
            label_Username.place(x=200, y=100)

            entry_Username=Entry(root, bd=2 ,font=(25))#user input
            entry_Username.pack() 
            entry_Username.place(x=200, y=120)

            button_Find=Button(root, text="Find",command=Find ,height=2, width=20, bd=3)#button runs Find() method
            button_Find.pack()
            button_Find.place(x=160,y=300)
            
            button_back=Button(root , command=back , text="Back", height=2, width=20, bd=3)#button takes you back to operations page 
            button_back.pack()
            button_back.place(x= 320, y=300)
        
        def Encryption():#button Encrption will call this method    
            dst()#destroy everything in the last page                 
            root.title("Encryption")#changing the title of the window
            root.geometry("600x450")#changing the size of the window

            def enc_back():#button Back will call this method
                operations(name)#It is will call the operations method to go back again to the operations page

            def encrybt():#button Encrybt will call this method
                if entry_file.get() != "":#if the file name entry that the user want to encrypt was not empty
                    if "\\" not in entry_file.get() :#if the user did not enter a path with file name
                        file=entry_file.get()#take the input from the user which is the file name that the user want to encrypt and save it in a new vairable 'file'
                        file=file[:-4]#delete the last four charactours of the extension
                        try:#to catch the exeptions
                            with open('keys/keyfile_'+file+'.txt','rb') as f:#open a file using 'file' variable for reading as a bytes
                                our_key = f.read()#read the random key that will be used to encrypt the file and save it in new variable 'our_key'
                        except FileNotFoundError:#catch the exeption of File not Found
                            messagebox.showerror("","File not Found in the Program Folder")#show an error message thet file not found in the program folder
                        AES_encryption(our_key,entry_file.get())#calling method AES_encryption() by entering as an input the variable 'our_key' and the input from the user
                        operations(name)#calling method operations() to make the user go back to th operations page again
                    else:#if the user entered a path with the file name
                        messagebox.showerror("","Inser the File Name only!")#show an error message that inser the file ame only
                else:#if the file name entry that the user want to encrypt was empty               
                    messagebox.showerror("","Blank Not Allowed")#show an error message that blank not allowed
        
            def AES_encryption(key,fileName,chunk_size=64*1024):#this method will be called from encrypt() method
                outputFile=fileName+'.encrypted'#making a decrypted file name using the fileName that comes as an input from encrypt() method 
                iv= 'This is an IV456'#16-byte initialization vector, its purpose is to produce different encrypted data. 
                encrypto=AES.new(key, AES.MODE_CBC,iv.encode('utf8'))#to generate AES encryption cipher(encrypto) using as an input the randome key, the aes mode, and initialization vector encoded(from string to bytes)
                try:#to catch the exeptions
                    filesize=os.path.getsize(fileName)#determining the size by the getsize() Function for using it in the file name >> (outputFile).
                    with open(fileName,'rb') as inputfile:#open the fileName that comes as an input from encrypt() method for reading as a byte
                        with open(outputFile,'wb') as outputfile:#open the outputFile the new variable that holds the encrypted file name for writing as a bytes
                            outputfile.write(struct.pack('<Q', filesize))#struct.pack() return a bytes object using filesize variable and it will be written in the file
                            outputfile.write(iv.encode('utf8'))#writing initialization vector encoded into the file
                            while True:
                                chunk=inputfile.read(chunk_size).decode('utf8')#read from the file as chunks multiple 16 bytes in size and decode it(from bytes to string).
                                if len(chunk)==0:#if there is no data to read
                                    break#stop
                                elif len(chunk)% 16 !=0:#if there is data and it's not multiple of 16 bytes in size
                                    chunk +=' '*(16-len(chunk)%16)#padding the data
                                outputfile.write(encrypto.encrypt(chunk.encode('utf8')))#the data is encrypted using encrypt() function and the variable chunk encoded(from string to bytes) then will be written into the file
                    
                except FileNotFoundError:#catch the exeption of File not Found
                    messagebox.showerror("","File not found in the program folder")#show an error message thet file not found in the program folder

            def encrypt_key():#button Encrypt random key will call this method
                try:#to catch the exeptions
                    if entry_reciver_key.get() != "" and entry_file.get() != "":#if the input of the reciver public key and the file name that the user want to encrypt were not empty
                        if "\\" not in  entry_file.get() != "":#if the user did not enter a path with file name
                            file=entry_file.get()#save the input of the file name that the user want to encrypt 
                            file=file[:-4]#delete the last four charactours of the extension
                            with open('keys/keyfile_'+file+'.txt','rb') as f:#open random key file using the file variable for reading as a bytes 
                                our_key = f.read(16)#read the 16 bytes random key
                            with open(entry_reciver_key.get(), 'rb') as p:#open reciver public key file with extension 'pem' that the user entered for reading as a bytes
                                publicKey = rsa.PublicKey.load_pkcs1(p.read())#using rsa for public key to load the key and sending as an input read() function
                
                            encryptedKey=rsa.encrypt(our_key, publicKey)#encrypt the random key using rsa encrypt method we will send the random key and reciver public key as an  input
                
                            with open('keys/EncryptedKey_'+file+'.txt','wb') as f:# open file using file name that the user want to encrypt 
                                f.write(encryptedKey)#save the encrypted random key on it
                            label_enc_key=Label(root, text="Key encrypted !",font=("Arial", 10))#inform the user that the random key encrypted by using lable
                            label_enc_key.pack()
                            label_enc_key.place(x=250, y=290)
                            filename='keyfile_'+entry_file.get()#save in a new variable the file name that the user want to encrypt
                            filename=filename[:-4]#delete the last four charactours of the extension
                            sign_sha1 (our_key, filename)#call sign_sha1() to make the signature of the random key by sending the random key and filename variable
                        else:#if the user entered a path with the file name
                            messagebox.showerror("","Inser the File Name only!")#show an error message that inser the file ame only
                    else:#if the input of th ereciver public key and the file name that the user want to encrypt were empty
                        messagebox.showerror("","Blank Not Allowed")#show an error a message that blank Not Allowed
                except FileNotFoundError:#catch the exeption of File not Found
                    messagebox.showerror("","File not Found in the Program Folder")#show an error message thet file not found in the program folder


            def aes_key():#button Generate random key will call this method
                if entry_file.get() != "":#if the file name that the user entered was not empty
                    if "\\" not in entry_file.get() :#if the user did not enter a path with file name
                        key = get_random_bytes(16)#saving 16 random bytes in a new variable  
                        key = bytes(key)#Convert it to byte
                        file=entry_file.get()#save the input of the file name that the user want to encrypt
                        file=file[:-4]#delete the last four charactours of the extension
                        
                        with open('keys/keyfile_'+file+'.txt','wb') as f:#open a file using the file name that the user want to encrypt for writing as a bytes
                            f.write(key)#write the random key 
                        label_aes_key=Label(root, text="Key generated !",font=("Arial", 10))#inform the user that the random key has been generated by using label
                        label_aes_key.pack()
                        label_aes_key.place(x=250, y=150)
                    else:#if the user entered a path with the file name
                        messagebox.showerror("","Inser the File Name only!!")#show an error message that inser the file ame only
                else:#if the file name that the user entered was empty
                    messagebox.showerror("","Blank Not Allowed")#show an error message that blank Not Allowed

            def sign_sha1 (randomkey, filename):#encrypt_key() method will call this method
                try:#to catch the exeptions
                   with open('keys/privateKey_'+name+'.pem', 'rb') as f:#open user private key with extension 'pem' by using his username for reading as a bytes
                        privkey = rsa.PrivateKey.load_pkcs1(f.read())#using rsa for private key to load the key and sending as an input read() function
                except FileNotFoundError:#catch the exeption of File not Found
                    messagebox.showerror("","File not found at the program folder!!")#show an error message thet file not found in the program folder
                signature= rsa.sign(randomkey, privkey, 'SHA-1')#create the signature using the random key and the user private key as sha-1
                with open('keys/sign_'+filename+'.txt', 'wb') as a:##open a file using filename that we recivet as an input for writing as a bytes
                    a.write(signature)#write the signature
            
            def Help():#button Help will call this method
                #will show an informational message that helps the users to get know how to use the encryption operation
                messagebox.showinfo("How to Use Me","1) Move the file to be encrypted to the program folder.\n2) Insert the file name only into the text field.\n3) Generate the ASE Random Key to Encrypt the file.\n4) Insert the receiver public key starting with \keys to encrypt the AES's key.\n5) Encrypt the key.\n6) Encrypt the file.")

            #----------------------------------------
            # Here is the page that helps the user to encrypt
            #---------------------------------------- 

            button_aes_key=Button(root , command=aes_key , text="Generate random key", height=1, width=20, bd=4)#button that runs aes_key() method
            button_aes_key.pack()
            button_aes_key.place(x= 220, y=110)

            button_enc_key=Button(root , command=encrypt_key , text="Encrypt random key", height=1, width=20, bd=4)#button that runs encrypt_key() method
            button_enc_key.pack()
            button_enc_key.place(x= 220, y=250)

            label_file=Label(root, text="Enter the file name to be encrypted:",font=("Arial", 10))#displays the what will be written in the entry_file 
            label_file.pack()
            label_file.place(x=190, y=40)

            entry_file=Entry(root, bd=2 ,font=(25))#user input for the file name
            entry_file.pack() 
            entry_file.place(x=190, y=70)

            label_reciver_key=Label(root, text="Enter reciver public key file name:",font=("Arial", 10))#displays the what will be written in the entry_reciver_key
            label_reciver_key.pack()
            label_reciver_key.place(x=190, y=180)

            entry_reciver_key=Entry(root,bd=2 ,font=(25)) #user input for reciver public key file name
            entry_reciver_key.pack()
            entry_reciver_key.place(x=190, y=210)

            button_encrybt=Button(root , command=encrybt , text="Encrybt", height=2, width=15, bd=3)#button that runs encrybt() method
            button_encrybt.pack()
            button_encrybt.place(x= 180, y=320)
            
            button_enc_back=Button(root , command=enc_back , text="Back", height=2, width=15, bd=3)#button takes you back to operations page 
            button_enc_back.pack()
            button_enc_back.place(x= 310, y=320)

            button_enc_back=Button(root , command=Help , text="Help", height=2, width=15, bd=3)#button that helps the users to get know how to use the encryption operation
            button_enc_back.pack()
            button_enc_back.place(x= 240, y=380)
            

        def Decryption():#button Decrption will call this method
            root.title("Decryption")#changing the title of the window
            root.geometry("600x450")#changing the size of the window
            dst()#dstroy evrything in the last page

            def dec_back():#button Back will call this method
                operations(name)#we will call operations() method to get back into the operations page

            def decrypt_key():#button Decrybt random key will call this method
                try:#to catch the exeptions
                    if entry_file.get()!= "":#if the file name that the user entered to be decrypted was not empty    
                        file=entry_file.get()#save the input of the file name that the user want to decrypt
                        file=file[:-14]#delete the last fourteen charactours to make the file like the original also for the extension
                        with open('database.txt', 'r') as f:#open the file database that saves all the users data for reading
                            if ('keys/privateKey_'+name+'.pem') in f.read():#if the user private key has been readed
                                with open('keys/privateKey_'+name+'.pem', 'rb') as f:#open user private key file with extension 'pem' for reading as a bytes
                                    privkey = rsa.PrivateKey.load_pkcs1(f.read())#using rsa for private key to load the key and sending as an input read() function
                        with open(entry_key1.get(),'rb') as p:#open the encrypted random key file name that the user entered for reading as a bytes
                            encryptedK=p.read()#read the encrypted random key and save it in a new variable
                        decrptedKey=rsa.decrypt(encryptedK,privkey)#decrypt the random key using rsa with method decrypt() that takes the encrypted random key and the user private key as an input
                        with open('keys/decrptedKey_'+file+'.txt','wb') as p:#open file using variable 'file' for writing as a bytes
                            p.write(decrptedKey)#write the decrypted random key
                        verify_shal(decrptedKey)#call method verify_shal and send as an input the decrypted random key to verify the random key.
                        entry_key=Label(root, text="Random key Decrypted",font=("Arial", 10))#inform the user that the random key has beet decrypted by using label
                        entry_key.pack()
                        entry_key.place(x=228, y=270)
                    else:#if the file name that the user entered to be decrypted was empty
                        messagebox.showerror("","Blank Not Allowed")#show an error message that blank Not Allowed
                except FileNotFoundError:#catch the exeption of file not found
                        messagebox.showerror("","file not found in the program folder!!")#show an error message thet file not found in the program folder


            def decrypt():#button Decrypt will call this method
                if entry_file.get() != "":#if the file name that the user entered to be decrypted was not empty 
                    if "\\" not in entry_file.get():#if the user did not enter a path with file name
                        file=entry_file.get()#save the input of the file name that the user want to encrypt
                        file=file[:-14]#delete the last fourteen charactours to make the file like the original also for the extension
                        
                        with open('keys/decrptedKey_'+file+'.txt','rb') as f:#open the decrypted random key file using variable file reading as a bytes
                            our_key = f.read()#read the random key and save it in our_key variable
                        decrypt_AES(our_key,entry_file.get())#calling decrypt_AES() to decrypt user's file
                        operations(name)#by calling this method the user will get back to the operations page
                    else:#if the user entered a path with the file name
                        messagebox.showerror("","Insert the File Name only!!")#show an error message that inser the file ame only
                else:#if the file name that the user entered to be decrypted was empty 
                    messagebox.showerror("","Blank Not Allowed")#show an error message that blank Not Allowed

            def decrypt_AES(key,fileName,chunk_size=24*1024):#decrypt() will call this method
                    try:#to catch the exeptions
                        output_file=os.path.splitext(fileName)[0]#the extension that was added previously (.encrypted) is removed by splittext() function
                        with open(fileName,'rb') as infile:#open fileName that comes as an input from decrypt() method
                            origsiz= struct.unpack('<Q',infile.read(struct.calcsize('Q')))[0]#readinf from the file
                            iv=infile.read(16)#read the 16 bytes initialization vector
                            decrp=AES.new(key,AES.MODE_CBC,iv)#for decryption the cipher by using the random key, aes mode, and initialization vector as an input
                            with open(output_file,'wb') as outfile:#open output_file file for writing as a bytes
                                while True:
                                    chunk=infile.read(chunk_size)#the data readed as chunks of multiple 16 bytes in size
                                    if len(chunk)==0:#If there is no data to read
                                        break#stop
                                    outfile.write(decrp.decrypt(chunk))#If there is data the data(chunk) is decrypted using the decrypt() function 
                                outfile.truncate(origsiz)#the padding is removed and returned to the original size.
                    except FileNotFoundError:#catch the exeption of file not found
                        messagebox.showerror("","File Not Found in the Program's Folder ")#show an error message thet file not found in the program folder
                
            def verify_shal(decrptedKey):#decrypt_key() method will call this method
                filename=entry_file.get()#save the input of the file name that the user want to decrypt
                filename=filename[:-14]#delete the last fourteen charactours to make the file like the original also for the extension
                try:#to catch the exeptions
                    with open('keys/sign_keyfile_'+filename+'.txt','rb') as a:#open the file that holds the signature using the filename variable for reading as a bytes
                        signature=a.read()#read from the file and save it in a new variable
                    with open(entry_sender_key.get(),'rb') as f:#open sender public key file with extension 'pem' that the user entered for reading as a bytes
                        pub= rsa.PublicKey.load_pkcs1(f.read())#using rsa for public key to load the key and sending as an input read() function
                    if rsa.verify (decrptedKey, signature, pub) == 'SHA-1' :#using rsa verify method that takes decrypted key, signature, and sender public key to verify the decrypted key if it equals to sha-1 
                        messagebox.showinfo("","Signature verified!")#will show an informational message that signature verified
                    else :#if does not equal to sha-1
                        messagebox.showerror("","Could not verify the message signature.")#will show an error message that could not verify the message signature
                except FileNotFoundError:#catch the exeption of file not found
                    messagebox.showerror("","File not found at the program folder")#show an error message thet file not found in the program folder
            
            def Help():#button Help will call this method
                #will show an informational message that helps the users to get know how to use the decryption  operation
                messagebox.showinfo("How to Use Me","1) Move the files to be Decrypt to the program folder.\n2) Insert the Encrypted Key's file name starting with keys\ into the text field. \n3) Insert the Encrypted file's name end with .encrypted only into text field to Decrypte it.\n4) Insert the sender's public key starting with keys\ to verify the signature.\n5) Decrypt The Key.\n6) Decrypt the File.")

            #----------------------------------------
            # Here is the page that helps the user to decrept
            #----------------------------------------     

            label_key=Label(root, text="Enter the encrypted key file name:",font=("Arial", 10))#displays the what will be written in the entry_key1
            label_key.pack()
            label_key.place(x=190, y=40)

            entry_key1=Entry(root,bd=2 ,font=(25))#user input for encrypted random key file name
            entry_key1.pack()
            entry_key1.place(x=190, y=60)

            label_file=Label(root, text="Enter encrypted file name:",font=("Arial", 10))#displays the what will be written in the entry_file
            label_file.pack()
            label_file.place(x=190, y=100)

            entry_file=Entry(root,bd=2 ,font=(25))#uer input for file name that the user want to decrypt
            entry_file.pack()
            entry_file.place(x=190, y=120)     

            label_sender_key=Label(root, text="Enter sender public key file name :",font=("Arial", 10))#displays the what will be written in the entry_sender_key
            label_sender_key.pack()
            label_sender_key.place(x=190, y=160)

            entry_sender_key=Entry(root,bd=2 ,font=(25))#user input for sender public key
            entry_sender_key.pack()
            entry_sender_key.place(x=190, y=180)

            button_decrybt_key=Button(root , command=decrypt_key , text="Decrybt random key", height=1, width=20, bd=3)#button that runs decrypt_key() method
            button_decrybt_key.pack()
            button_decrybt_key.place(x= 225, y=230)

            button_decrybt=Button(root , command=decrypt , text="Decrybt", height=2, width=15, bd=3)#button that runs decrypt() method
            button_decrybt.pack()
            button_decrybt.place(x= 180, y=320)

            button_dec_back=Button(root , command=dec_back , text="Back", height=2, width=15, bd=3)#button takes you back to operations page
            button_dec_back.pack()
            button_dec_back.place(x= 310, y=320)

            button_dec_Help=Button(root , command=Help , text="Help", height=2, width=15, bd=3)#button that helps the users to get know how to use the encryption operation
            button_dec_Help.pack()
            button_dec_Help.place(x= 240, y=380)

        dst()#dstroy evrything in the last page 
        root.title("Opartion")#changing the title of the window
        root.geometry("600x450")#changing the size of the window

        #----------------------------------------
        # Here is the page that asks the user about his\her choice
        #---------------------------------------- 

        button_Encrption=Button(root , command=Encryption , text="Encryption", height=2, width=20, bd=3)#button that runs Encryption() method
        button_Encrption.pack()
        button_Encrption.place(x= 240, y=130)
        
        button_Decrption=Button(root,command=Decryption, text="Decryption", height=2, width=20, bd=3)#button that runs Decryption() method
        button_Decrption.pack()
        button_Decrption.place(x= 240, y=190)

        button_Find=Button(root,command=find_keys, text="Find keys", height=2, width=20, bd=3)#button that runs find_keys() method
        button_Find.pack()
        button_Find.place(x= 240, y=250)

        button_Back=Button(root,command=all, text="Logout", height=2, width=20, bd=3)#button to go back to login page
        button_Back.pack()
        button_Back.place(x= 240, y=310)

        label_public_key=Label(root, text="Your public key is: keys/publicKey_"+name+".pem",font=("Arial", 10))#displays user's public key
        label_public_key.pack()
        label_public_key.place(x=140, y=50)

        label_private_key=Label(root, text="Your private key is: keys/privateKey_"+name+".pem",font=("Arial", 10))#displays user's private key
        label_private_key.pack()
        label_private_key.place(x=140, y=80)


    def signup():
        dst()#dstroy evrything in the last page          
        def generateKeys(Username):#method register() will call this method after saving the username and the password in the file
            root.title("Key generation")#changing the title of the window
            root.geometry("600x450")#changing the size of the window
            dst()#dstroy evrything in the last page
            def Generate_key():#button Generate your keys will call this method 
                
                def start():#button Start will call this method
                    operations(Username)#calling operations() method to go to operations page

                (publicKey, privateKey) = rsa.newkeys(1024)#create keys of 1024 bits and will save them into a tuple of public and private keys
                pub='keys/publicKey_'+Username+'.pem'#public key file name with extension 'pem' using a username and save it in a vairable
                priv='keys/privateKey_'+Username+'.pem'#private key file name with extension 'pem' using a username and save it in a vairable
                with open(pub, 'wb') as p:#open the public key file 
                    p.write(publicKey.save_pkcs1('PEM'))#public key are saved in pem format by using the save_pkcs1('PEM') function
                with open(priv, 'wb') as p:#open the private key file 
                    p.write(privateKey.save_pkcs1('PEM'))#private are saved in pem format by using the save_pkcs1('PEM') function
                db = open("database.txt", "a")#open the database file
                db.write(" , "+pub+", "+priv+"\n")#write in the in the database file the public and private keys
                
                #----------------------------------------
                # Here is the page that inform the user that they have keys now and they can enter the system.
                #---------------------------------------- 

                label_pubkey=Label(root, text="Your public key file name is : " + pub ,font=("Arial", 10))#displays user public key
                label_pubkey.pack()
                label_pubkey.place(x=120, y=100)

                label_privkey=Label(root, text="Your private key file name is : " + priv ,font=("Arial",10))#displays user private key
                label_privkey.pack()
                label_privkey.place(x=120,y=160)

                button_pubkey=Button(root, text="Start",command=start ,height=2, width=20, bd=3)#button that runs start() method
                button_pubkey.pack()
                button_pubkey.place(x=240,y=300)

            #----------------------------------------
            # Here is the page that inform the user that they dont have keys and they should create one.
            #---------------------------------------- 

            label_pubkey=Label(root, text="Your public key file name is : NONE",font=("Arial", 10))#displays that there is no public key for you yet
            label_pubkey.pack()
            label_pubkey.place(x=120, y=100)

            label_privkey=Label(root, text="Your private key file name is : NONE",font=("Arial",10))#displays that there is no private key for you yet
            label_privkey.pack()
            label_privkey.place(x=120,y=160)

            button_pubkey=Button(root, text="Generate your keys",command=Generate_key ,height=2, width=20, bd=3)#button that runs Generate_key() method
            button_pubkey.pack()
            button_pubkey.place(x=240,y=300) 
            
        root.title("Signup")#changing the title of the window
        root.geometry("600x450")#changing the size of the window
        def register():#button'Next' will run this method that will regist the user
            if entry_username.get() != "" and entry_password.get() != "" and entry_password2.get() != "":#if entry_username, entry_password, and entry_password2 was not empty
                Username=entry_username.get()#take the input username from the user
                Password1=entry_password.get()#take the input password from the user
                Password2=entry_password2.get()#take the input password again from the user
                db = open("database.txt", "r")#open the file database that saves all the users data for reading
                database = []#create new array
                for i in db:#in each line in this file
                    a,b,y,z = i.split(",")#The split() function returns the strings as a list separted by comma
                    database.append(a)#add the username in usernames list
                if not len(Password1)<=8:#the password from the user must be more than 8 character
                    if Username in database:#if the username that the user picked in the file
                        messagebox.showinfo("","You already have an account")#show an information message that you already have an account
                        signup()#call method signup() to make the entrys clear		
                    else:
                        if Password1 == Password2:# if the two password form the user matched
                            Password1 = Password1.encode('utf-8')#encode() returns the byet of the password
                            Password1 = bcrypt.hashpw(Password1, bcrypt.gensalt())#hash the password by using method hashpw()
                            db = open("database.txt", "a")#open the file database that saves all the users data for writing      
                            db.write(Username+", "+str(Password1))#write in the file database the username and the password as a string and separate it by comma
                            messagebox.showinfo("","User created successfully!")#show an informaton message that the user created successfully
                            generateKeys(Username)#after the creation the user must create the keys by using this method
                        else:#if does not match 
                            messagebox.showerror("","Passwords do not match")#show an error message that passwords do not match
                else:#if the password less than 9 
                    messagebox.showerror("","Password too short, You must enter greater than 8 characters.")#show an error message that the password too short
            else:#if entry_username, entry_password, and entry_password2 was empty 
                messagebox.showerror("","Blank Not Allowed")#show an error message that the blank Not Allowed
        

        def back():# the button 'Back' will call this method that's call method all()
            all()#go back to login page

        #----------------------------------------
        # Here is the page that the user can create new account
        #---------------------------------------- 

        label_Username=Label(root, text="Username",font=("Arial", 10))#displays the what will be written in the entry_username
        label_Username.pack()
        label_Username.place(x=200, y=80)

        entry_username=Entry(root, bd=2 ,font=(25))#user input for his username
        entry_username.pack()
        entry_username.place(x=200, y=120)

        label_Password=Label(root, text="Password",font=("Arial",10))#displays the what will be written in the entry_password
        label_Password.pack()
        label_Password.place(x=200,y=160)
        
        entry_password=Entry(root, bd=2 ,font=(25),show = '*')#user input for his password 
        entry_password.pack()
        entry_password.place(x=200, y=200)

        label_password2=Label(root, text="Enter your password again",font=("Arial",10))#displays the what will be written in the entry_password2
        label_password2.pack()
        label_password2.place(x=200,y=240)

        entry_password2=Entry(root, bd=2 ,font=(25),show = '*')#user input for his password again
        entry_password2.pack()
        entry_password2.place(x=200, y=280)
        
        button_back=Button(root, text="Back", command=back, height=2, width=15, bd=3)#button to go back to login bage
        button_back.pack()
        button_back.place(x= 320, y=340)
        
        button_next=Button(root, text="Next", command=register, height=2, width=15, bd=3)#button that runs Generate_key() method
        button_next.pack()
        button_next.place(x= 190, y=340)
 
    def gainAccess(Username=None, Password=None):#for login in the system
        if Username_entry.get() != "" and Password_entry.get() != "":#if the Username_entry and Password_entry was not empty
            Username=Username_entry.get()#take the input username from the user
            Password=Password_entry.get()#take the input password from the user             
            db = open("database.txt", "r")# open the file database that saves all the users data
            Usernames = []#create a new array to save all the usernames on it
            Passwords = []#create a new array to save all the passwords on it
            for i in db:#return each line in the file
                a,b,y,z = i.split(",")#The split() function returns the strings as a list separted by comma
                b = b.strip()#the strip() method is to remove the whitespace from the beginning and at the end of the string
                Usernames.append(a)#add the username in usernames list
                Passwords.append(b)#add the username in passwords list
                #zip() function that will aggregate elements from two or more
                #dict() Dictionaries are used to store data values in key:value pairs.
                data = dict(zip(Usernames, Passwords))
            if Username in data:#if the user are already signup the database(our file) 
                hashed = data[Username].strip('b')#take the second element in the list that have the same username
                hashed = hashed.replace("'", "")#delete backtick around the hashed password
                hashed = hashed.encode('utf-8')#conver it from string to byte
                Password = Password.encode('utf-8')#conver it from string to byte
                if bcrypt.checkpw(Password, hashed):#checkpw(passwd, hashedPasswd) Check that a unhashed password matches the hashed password.
                    messagebox.showinfo("","Hi : " + Username)#if matched show an information message theat welcoming for the user
                    operations(Username)#move the user to the oparetions page
                else:#if the passwords do not match
                    messagebox.showerror("","Wrong password")#show an error message that wrong password
            else:#If the user is not registere
                messagebox.showerror("","Username doesn't exist")#show an error message that username doesn't exist
                all()#go back to login again to clear the entries
        else:#if the Username_entry and Password_entry was empty
            messagebox.showerror("","Blank Not Allowed")#show an error message that the balnk not allowed
            
    #----------------------------------------
    # Here is the first page in the gui that asks the user to login or signup
    #----------------------------------------

    Username=Label(root, text="Username",font=("Arial", 12))#displays the what will be written in the Username_entry
    Username.pack()
    Username.place(x=200, y=100)
    
    Username_entry=Entry(root, bd=2 ,font=(25))#user input for his username
    Username_entry.pack()
    Username_entry.place(x=200, y=150)

    Password=Label(root, text="Password",font=("Arial",12))#displays the what will be written in the Password_entry
    Password.pack()
    Password.place(x=200,y=200)

    Password_entry=Entry(root, bd=2 ,font=(25),show = '*')#user input for his password
    Password_entry.pack()
    Password_entry.place(x=200, y=250)

    Login=Button(root, text="Login", command=gainAccess, height=2, width=15, bd=3)#button that runs gainAccess() method
    Login.pack()
    Login.place(x= 190, y=300)
    
    Signup=Button(root, text="Signup", command=signup, height=2, width=15, bd=3)#button that runs signup() method
    Signup.pack()
    Signup.place(x= 320, y=300)
        
all()#to run the program

#mainloop() tells Python to run the Tkinter event loop. 
#This method listens for events, such as button clicks or keypresses
#and blocks any code that comes after it from running until you close the window
root.mainloop()
