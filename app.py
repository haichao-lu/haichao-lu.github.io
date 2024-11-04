import os
from datetime import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""

    if request.method == "POST":
        add = request.form.get("add")
        if not add:
            return apology("must provide cash amount", 400)
        try:
            add = float(add)
        except ValueError:
            return apology("not valid cash amount", 400)
        if add < 0:
            return apology("not valid cash amount", 400)

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        cash += add
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
        return redirect("/")

    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    stocks = db.execute("SELECT stock, sum(shares) FROM history WHERE user_id = ? GROUP BY stock HAVING sum(shares) > 0",
                        session["user_id"])
    holding = []
    total_value = 0
    for s in stocks:
        stock = s["stock"].upper()
        price = float(lookup(s["stock"])["price"])
        shares = s["sum(shares)"]
        value = price * shares
        total_value += value
        holding.append({"stock": stock, "shares": shares, "price": price, "value": value})
    asset = cash + total_value

    return render_template("index.html", asset=asset, total_value=total_value, cash=cash, holding=holding)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        # Check the validity of input
        stock = request.form.get("symbol")
        if not stock or not request.form.get("shares"):
            return apology("must provide symbol and shares", 400)
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("shares must be a positive integer", 400)
        if shares < 1:
            return apology("shares must be a positive integer", 400)

        # Look up the quote data
        quote_data = lookup(stock)
        if not quote_data:
            return apology("symbol does not exist", 400)

        # Check the ability to buy
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        price = float(quote_data["price"])
        if cash < shares * price:
            return apology("not enough cash", 400)
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Insert buying history into database and update the cash
        db.execute("INSERT INTO history (user_id, stock, shares, price, time) VALUES(?, ?, ?, ?, ?)",
                   session["user_id"], stock, shares, price, time)
        cash -= shares * price
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])

        return redirect('/')

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    data = db.execute(
        "SELECT stock, price, shares, time FROM history WHERE user_id = ?", session["user_id"])
    history = []
    for d in data:
        stock = d["stock"].upper()
        price = d["price"]
        shares = abs(d["shares"])
        if d["shares"] > 0:
            type = "Buy"
        else:
            type = "Sell"
        time = d["time"]
        history.append({"stock": stock, "price": price,
                       "shares": shares, "type": type, "time": time})

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        # Check the validity of symbol
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        # Look up the quote data
        quote_data = lookup(request.form.get("symbol"))
        if not quote_data:
            return apology("symbol does not exist", 400)
        return render_template("quoted.html", quote_data=quote_data)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        # Check the validity of the input
        if not request.form.get("username"):
            return apology("must provide username", 400)
        if not request.form.get("password") or not request.form.get("confirmation"):
            return apology("must provide and confirm password", 400)
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password is not confirmed", 400)

        # Create a new account
        hash = generate_password_hash(request.form.get("password"))
        try:
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                       request.form.get("username"), hash)
            return redirect("/login")
        except ValueError:
            return apology("username already exists", 400)

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        # Check the validity of input
        stocks = db.execute(
            "SELECT stock FROM history WHERE user_id = ? GROUP BY stock HAVING sum(shares) > 0", session["user_id"])
        stock = request.form.get("symbol")
        if {"stock": stock} not in stocks or not request.form.get("shares"):
            return apology("invalid symbol and/or shares", 400)
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("shares must be a positive integer", 400)
        if shares < 1:
            return apology("shares must be a positive integer", 400)

        # Look up the quote data
        quote_data = lookup(stock)
        if not quote_data:
            return apology("symbol does not exist", 400)

        # Check the ability to sell
        holding = db.execute("SELECT sum(shares) FROM history WHERE user_id = ? AND stock = ?",
                             session["user_id"], stock)[0]["sum(shares)"]
        if shares > holding:
            return apology("not enough holding", 400)

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        price = float(quote_data["price"])
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Insert selling history into database and update the cash
        db.execute("INSERT INTO history (user_id, stock, shares, price, time) VALUES(?, ?, ?, ?, ?)",
                   session["user_id"], stock, -shares, price, time)
        cash += shares * price
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])

        return redirect('/')

    holding = db.execute(
        "SELECT stock FROM history WHERE user_id = ? GROUP BY stock HAVING sum(shares) > 0", session["user_id"])
    return render_template("sell.html", holding=holding)
