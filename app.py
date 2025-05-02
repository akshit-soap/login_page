import streamlit as st
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import hashlib

# Connect to MongoDB using Streamlit secrets
def connect_db():
    uri = "mongodb+srv://akshit:uvO7vHUnTiwhvnmO@cluster0.uhkbybn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    client = MongoClient(uri, server_api=ServerApi('1'))
    db = client["user_akshit"]  # Make sure your DB name matches
    return db["users"]  # Collection name

# Hash the password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Insert a new user into MongoDB
def insert_user(username, email, password):
    users = connect_db()
    if users.find_one({"username": username}):
        st.warning("Username already exists.")
        return False
    try:
        users.insert_one({
            "username": username,
            "email": email,
            "password": hash_password(password)
        })
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

# Authenticate login credentials
def login_user(username, password):
    users = connect_db()
    user = users.find_one({
        "username": username,
        "password": hash_password(password)
    })
    return user

# Streamlit UI logic
def main():
    st.set_page_config(page_title="Login/Signup App", layout="centered")
    
    if 'page' not in st.session_state:
        st.session_state.page = "signup"

    if st.session_state.page == "signup":
        st.title("Signup Page")

        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")

        if st.button("Create Account"):
            if password != confirm:
                st.warning("Passwords do not match")
            elif username and email and password:
                if insert_user(username, email, password):
                    st.success("Account created successfully!")
                    st.session_state.page = "login"
            else:
                st.warning("Please fill in all fields.")

        if st.button("Go to Login"):
            st.session_state.page = "login"

    elif st.session_state.page == "login":
        st.title("Login Page")

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            user = login_user(username, password)
            if user:
                st.success(f"Welcome, {username}!")
                st.balloons()
                st.write("You're logged in.")
            else:
                st.error("Invalid credentials")

        if st.button("Go to Signup"):
            st.session_state.page = "signup"

if __name__ == "__main__":
    main()
