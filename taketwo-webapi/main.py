from dotenv import load_dotenv
load_dotenv()

import os
import json

from typing import Optional

from fastapi import FastAPI, Depends, FastAPI, HTTPException, status
from pydantic import BaseModel

from fastapi.responses import HTMLResponse

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
import base64

import couchdb

import jwt
from passlib.context import CryptContext
from jwt import PyJWTError

from datetime import timedelta,datetime

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7" #TODO change and move to .env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

clear_token = os.getenv("CLEAR_TOKEN")
db_name = os.getenv("DB_NAME")
db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT")
db_username = os.getenv("DB_USERNAME")
db_password = os.getenv("DB_PASSWORD")

client = None
db = None
creds = None

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def retrieve_token(username, password):

    client_id = os.getenv("CLIENT_ID")
    secret = os.getenv("SECRET")
    url = os.getenv("OAUTH_SERVER_URL") + "/token"
    grant_type = "password"

    usrPass = client_id + ":" + secret
    b64Val = base64.b64encode(usrPass.encode()).decode()
    headers = {"accept": "application/json", "Authorization": "Basic %s" % b64Val}

    data = {
        "grant_type": grant_type,
        "username": username,
        "password": password,
        "scope": "all",
    }

    response = httpx.post(url, headers=headers, data=data)

    if response.status_code == httpx.codes.OK:
        return response.json()
    else:
        raise HTTPException(status_code=response.status_code, detail=response.text)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def validate(token: str = Depends(oauth2_scheme)):
    if os.getenv("AUTH_PROVIDER") == "AppID":
        return validate_token_IBM(
        token, os.getenv("OAUTH_SERVER_URL"), os.getenv("CLIENT_ID"), os.getenv("SECRET")
    )
    return validate_token_local(token)

def validate_token_local(token, str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except PyJWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user
    
def validate_token_IBM(token, authURL, clientId, clientSecret=Depends(oauth2_scheme)):
    usrPass = clientId + ":" + clientSecret
    b64Val = base64.b64encode(usrPass.encode()).decode()
    # headers = {'accept': 'application/json', 'Authorization': 'Basic %s' % b64Val}
    headers = {
        "accept": "application/json",
        "cache-control": "no-cache",
        "content-type": "application/x-www-form-urlencoded",
        "Authorization": "Basic %s" % b64Val,
    }
    data = {
        "client_id": clientId,
        "client_secret": clientSecret,
        "token": token,
    }
    url = authURL + "/introspect"

    response = httpx.post(url, headers=headers, data=data)

    if response.status_code == httpx.codes.OK and response.json()["active"]:
        return jwt.decode(token, options={"verify_signature": False})
    else:
        raise HTTPException(status_code=403, detail="Authorisation failure")


client = couchdb.Server(f'http://{db_username}:{db_password}@{db_host}:{db_port}/')
try: 
    db = client.create(db_name)
except couchdb.PreconditionFailed:
    db = client[db_name]


class Flagged(BaseModel):
    _id: Optional[str]
    user_id: str
    flagged_string: str
    category: str
    info: Optional[str]
    url: str


class Text(BaseModel):
    content: str


@app.get("/", response_class=HTMLResponse)
def read_root():
    return open("template.html").read()


# Get auth token
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if os.getenv("AUTH_PROVIDER") == "AppID":
        """
        Gets a token from IBM APP ID, given a username and a password. Depends on OAuth2PasswordRequestForm.
        Parameters
        ----------
        OAuth2PasswordRequestForm.form_data.username: str, required
        OAuth2PasswordRequestForm.form_data.password: str, required
        Returns
        -------
        token: str
        """
        return retrieve_token(form_data.username, form_data.password)
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/mark")
def get_marks(user: dict = Depends(validate)):
    return list(map(lambda item: dict(item.doc.items()), db.view('_all_docs',include_docs=True)))


@app.post("/mark")
def save_mark(item: Flagged, user: dict = Depends(validate)):
    item.user_id = user["sub"]
    data = item.dict()
    _id, _ = db.save(data)
    return data


@app.put("/mark/{_id}")
def update_mark(_id: str, item: Flagged, user: dict = Depends(validate)):
    doc = db[_id]
    doc["category"] = item.category
    db[doc.id] = doc
    return {"status": "success"}


@app.delete("/mark")
def delete_mark(_id: str, user: dict = Depends(validate)):
    my_document = db[_id]
    db.delete(my_document)
    return {"status": "success"}


@app.get("/categories")
def read_categories():
    # fmt: off
    return [
        #IBM colour-blindness palette used below https://davidmathlogic.com/colorblind/ 
        {
            "name": "appropriation", 
            "colour": "#648FFF", 
            "description": "To adopt or claim elements of one or more cultures to which you do not belong, consequently causing offence to members of said culture(s) or otherwise achieving some sort of personal gain at the expense of other members of the culture(s)."
        },
        {
            "name": "stereotyping",
            "colour": "#785EF0",
            "description": "To perpetuate a system of beliefs about superficial characteristics of members of a given ethnic group or nationality, their status, society and cultural norms.",
        },
        {
            "name": "under-representation",
            "colour": "#DC267F",
            "description": "To have Insufficient or disproportionately low representation of Black, Indigenous, People of Color (BIPOC) individuals, for example in mediums such as media and TV adverts.",
        },
        {
            "name": "gaslighting", 
            "colour": "#FE6100", 
            "description": "To use tactics, whether by a person or entity, in order to gain more power by making a victim question their reality.  To deny or refuse to see racial bias, which may also include the act of convincing a person that an event/slur/idea is not racist or not as bad as one claims it to be through means of psychological manipulation."
        },
        {
            "name": "racial-slur",
            "colour": "#FFB000",
            "description": "To insult, or use offensive or hurtful language designed to degrade a person because of their race or culture. This is intentional use of words or phrases to speak of or to members of ethnical groups in a derogatory manor. ",
        },
        {
            "name": "othering", 
            "colour": "#5DDB2B", 
            "description": "To label and define a person/group as someone who belongs to a 'socially subordinate' category of society. The practice of othering persons means to use the characteristics of a person's race to exclude and displace such person from the 'superior' social group and separate them from what is classed as normal."
        },
    ]
    # fmt: on


@app.put("/analyse")
def analyse_text(text: Text):
    res = []
    for item in db.view('_all_docs',include_docs=True):
        doc = item.doc
        if doc["flagged_string"] in text.content:
            res.append({"flag" : doc["flagged_string"], "category" : doc["category"], "info" : doc["info"]})
    return {"biased": res}

@app.put("/check")
def check_words(text: Text):
    res = []
    for item in db.view('_all_docs',include_docs=True):
        doc = item.doc
        if doc["category"] == "racial slur" and doc["flagged_string"].lower() in text.content.lower():
            res.append({"flag" : doc["flagged_string"], "category" : doc["category"], "info" : doc["info"]})
    
    line_by_line = []
    for i,l in enumerate(text.content.splitlines(),1):
        for r in res:
            if r["flag"].lower() in l.lower():
                line_by_line.append({
                    "line" : i,
                    "word" : r["flag"],
                    "additional_info": r["info"]
                })

    return line_by_line

