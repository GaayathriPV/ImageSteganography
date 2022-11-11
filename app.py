from flask import Flask, render_template, request, flash, redirect, send_file, url_for, session
#from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import os
import cv2

key = Fernet.generate_key()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost:5432/flasksql'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = 'secret string'

db = SQLAlchemy(app)
#migrate = Migrate(app,db)
UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# creating user database
class UserModel(db.Model):
    __tablename__ = 'user'
    email = db.Column(db.String(200), nullable=False, primary_key=True)
    pwd = db.Column(db.String(50), nullable=False)

    def __init__(self, email, pwd):
        self.email = email
        self.pwd = pwd

    def __repr__(self):
        return f"<User {self.email}>"

@app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'pwd' in request.form:
        email = request.form['email']
        pwd = request.form['pwd']
        account = db.session.query(UserModel).filter(UserModel.email==email and UserModel.pwd==pwd)
        if account:
            session['loggedin'] = True
            session['email'] = email
            msg = 'OTP required'
            return render_template('login_2fa.html', msg = msg)
        else:
            msg = 'Incorrect email / pwd !'
    return render_template('login.html', msg = msg)

@app.route('/login_2fa', methods=['GET', 'POST'])
def login_2fa():
    msg = ''
    if request.method == 'POST':
        msg = 'Logged in successfully !'
        return render_template('index.html', msg = msg)
    return render_template('index.html', msg = msg)

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('email', None)
    return redirect(url_for('login'))

@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'pwd' in request.form and 'email' in request.form :
        email = request.form['email']
        pwd = request.form['pwd']
        account = db.session.query(UserModel).filter(UserModel.email==email)
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', email):
            msg = 'Username must contain only characters and numbers !'
        elif not email or not pwd or not email:
            msg = 'Please fill out the form !'
        else:
            new_user=UserModel(email,pwd)
            db.session.add(new_user)
            db.session.commit()
            msg = 'You have successfully registered !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('register.html', msg = msg)

@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if request.form['button'] == "SteganographyEncryption":
            return render_template('encryption.html')
        elif request.form['button'] == "SteganographyDecryption":
            return render_template('decryption.html')
        
    return "Invalid operation :("

    
@app.route('/encryption', methods=['GET', 'POST'])
def encryption():
    if request.method == 'POST':
        text_data = request.form['text']
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        imag=cv2.imread(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        '''message = text_data.encode()
        f = Fernet(key)
        encrypted = f.encrypt(message)'''
        encode_data(imag, text_data)
        return "Image Encoded with text is saved in your device under the name encoded_img.png"
    return render_template('encryption.html')

def message2binary(message):
    if type(message) == str:
        result= ''.join([ format(ord(i), "08b") for i in message ]) #08b is used as we need 8-bit representation of binary digits 
    
    elif type(message) == bytes or type(message) == np.ndarray:
        result= [ format(i, "08b") for i in message ]
    
    elif type(message) == int or type(message) == np.uint8:
        result=format(message, "08b")

    else:
        raise TypeError("Input type is not supported")
    
    return result


def encode_data(img, txt):
    list1=[ ]
    data=txt    
    if (len(data) == 0): 
      raise ValueError('Data is empty')
  
    filename = "encoded_img.png" 
    
    # we need bytes because only LSB of each byte is overwritten with data
    no_bytes=(img.shape[0] * img.shape[1] * 3) // 8 
    
    #print("Maximum bytes to encode:", no_bytes)
    
    if(len(data)>no_bytes):
        raise ValueError("Error encountered Insufficient bytes, Need Bigger Image or give Less Data !!")
    
    # Using the below as delimeter
    data +='*****'    
    
    data_binary=message2binary(data)
    #print(data_binary)
    data_len=len(data_binary)
    
    #print("The Length of Binary data",data_len)
    
    data_index = 0
    
    for i in img:
        for pixel in i:
            
          r, g, b = message2binary(pixel)
         # print(r)
         # print(g)
         # print(b)
        #   print(pixel)
          if data_index < data_len:
              # hiding the data into LSB(Least Significant Bit) of Red Pixel
#               print("Original Binary",r)
              # print("The old pixel",pixel[0])
              pixel[0] = int(r[:-1] + data_binary[data_index], 2) #changing to binary after overwrriting the LSB bit of Red Pixel
#               print("Changed binary",r[:-1] + data_binary[data_index])
              
              data_index += 1
              list1.append(pixel[0])

          if data_index < data_len:
             # hiding the data into LSB of Green Pixel
              pixel[1] = int(g[:-1] + data_binary[data_index], 2) #changing to binary after overwrriting the LSB bit of Green Pixel
              data_index += 1
              list1.append(pixel[1])

          if data_index < data_len:
              # hiding the data into LSB of  Blue Pixel
              pixel[2] = int(b[:-1] + data_binary[data_index], 2) #changing to binary after overwrriting the LSB bit of Blue pixel
              data_index += 1
              list1.append(pixel[2])

              # if data is encoded, just breaking out of the Loop
          if data_index >= data_len:
              break

         
  
    cv2.imwrite(filename,img)
    #print("Encoded the data successfully and the image is successfully saved as ",filename)



@app.route('/decryption', methods=['GET', 'POST'])
def decryption():
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        imag=cv2.imread(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        data = decode_data(imag)
        '''f = Fernet(key)
        decrypted = f.decrypt(data).decode()'''
        return "Encoded Data is: "+data
    return render_template('decryption.html')

def decode_data(img):
    
    binary_data = ""
    for i in img:
        for pixel in i:
        
        #   print(pixel)
            r, g, b = message2binary(pixel) 
            binary_data += r[-1]  #Extracting Encoded data from the LSB bit of Red Pixel as we have stored in LSB bit of every pixel.
            binary_data += g[-1]  #Extracting Encoded data from the LSB bit of Green Pixel
            binary_data += b[-1]  #Extracting Encoded data from LSB bit of Blue Pixel

  # splitting by 8-bits
    all_bytes = [ binary_data[i: i+8] for i in range(0, len(binary_data), 8) ]

  # Converting the bits to Characters
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-5:] == "*****": #Checking if we have reached the delimeter which is "*****"
            break

    return decoded_data[:-5]
    #print("The Encoded data was :--",decoded_data[:-5])

if __name__ == '__main__':
    db.create_all()
    app.debug=True
    app.run()