from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import json
from cryptography.fernet import Fernet
from fastapi.middleware.cors import CORSMiddleware
import jwt
from datetime import date
from typing import Tuple


app = FastAPI()

Secret_key = "ABC"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_data(data):
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(encrypted_data):
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except Exception as e:
        print("Error during decryption:", e)
        return None

class UserData(BaseModel):
    username: str
    email: str
    password: str
    retype_password: str
    dateOfBirth: str

class UserDataE(BaseModel):
    email: str
    password: str

class TicketBooking(BaseModel):
 date: date
 adult_tickets: int
 child_tickets: int
 elder_tickets: int

@app.post("/book_ticket/")
async def book_ticket(ticket_booking: TicketBooking) -> Tuple[date, list]:
    if ticket_booking.adult_tickets + ticket_booking.child_tickets + ticket_booking.elder_tickets == 0:
        raise HTTPException(status_code=400, detail="You have to choose at least one ticket")

    chosen_tickets = []

    if ticket_booking.adult_tickets > 0:
        chosen_tickets.append({"type": "adult", "quantity": ticket_booking.adult_tickets})
    if ticket_booking.child_tickets > 0:
        chosen_tickets.append({"type": "child", "quantity": ticket_booking.child_tickets})
    if ticket_booking.elder_tickets > 0:
        chosen_tickets.append({"type": "elder", "quantity": ticket_booking.elder_tickets})

    return ticket_booking.date, chosen_tickets


@app.post("/register/")
async def register(user_data: UserData):
    if user_data == "":
        raise HTTPException(status_code=400, detail="Please enter in you detail")
    if user_data.password != user_data.retype_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    elif user_data.email == "":
        raise HTTPException(status_code=400, detail="email is needed")
    elif len(user_data.password) <= 7:
        raise HTTPException(status_code=400, detail="Password needs 8 or more characters")
    token1 = jwt.encode({"username": user_data.email}, Secret_key, algorithm="HS256")  

    encrypted_user_data = {
        "username":  (user_data.username) if user_data.username else None,
        "email": (user_data.email),
        "password": (user_data.password),
        "retype_password": (user_data.retype_password) if user_data.retype_password else None,
        "dateOfBirth": (user_data.dateOfBirth) if user_data.dateOfBirth else None
    }
   # I was origanly going to enctypt user-data however I'm having problem with decyption
    ##encrypted_user_data = {
    ##    "username": encrypt_data (user_data.username) if user_data.username else None,
   ##     "email": encrypt_data(user_data.email),
   ##     "password": encrypt_data(user_data.password),
   ##     "retype_password": encrypt_data(user_data.retype_password) if user_data.retype_password else None,
    ##    "dateOfBirth": encrypt_data(user_data.dateOfBirth) if user_data.dateOfBirth else None
 ## }

    with open("user_data.json", "a+") as f:
        f.write(json.dumps(encrypted_user_data) + "\n")
     

    return {"message": "User registered successfully", "token" : token1}

@app.post("/login/")
async def login(user_data: UserDataE):
    with open("user_data.json", "r") as f:
        for line in f:
            decrypted_user_data = json.loads(line)
            if ((decrypted_user_data["email"]) == user_data.email and
                (decrypted_user_data["password"]) == user_data.password):
                token = jwt.encode({"username": user_data.email}, Secret_key, algorithm="HS256")
                return {"message": "Login successful", "token": token}
            else:
                 raise HTTPException(status_code=400, detail="User not in database")


    


