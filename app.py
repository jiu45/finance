import os

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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""


    shares = db.execute("SELECT symbol, SUM(shares_change) AS s FROM commands WHERE id = ? GROUP BY symbol", session["user_id"])
    check_price = []
    total_stock = 0
    for share in shares:
        if share["s"] == 0:
            continue
        key = lookup(share["symbol"])
        key["shares"] = share["s"]
        key["total"] = round(key["shares"] * key["price"], 2)
        check_price.append(key)
        total_stock+= key["total"]

    cash_bf = db.execute("SELECT remaining FROM commands WHERE id = ? ORDER BY transacted DESC LIMIT 1", session["user_id"])
    if len(cash_bf) != 1:

        TOTAL = usd(session["user_first_cash"])
        cash = TOTAL

    else:
        cash = usd(cash_bf[0]["remaining"])
        TOTAL = usd(cash_bf[0]["remaining"] + total_stock)

    return render_template("index.html", check_price=check_price, cash=cash, TOTAL=TOTAL)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares_bf = request.form.get("shares")
        shares = int(shares_bf)

        if not symbol:
            return apology("Missing symbol")
        if not shares:
            return apology("Missing shares")


        data = lookup(symbol)

        if data == None:
            return apology("Invalid Symbol", 500)

        user_command = db.execute("SELECT * FROM commands WHERE id = ?", session["user_id"])

        this = data["price"] * shares

        if len(user_command) == 0:

            if session["user_first_cash"] < this:
                return apology("Insufficient", 501)
            else:
                remaining = session["user_first_cash"] - this
                db.execute("INSERT INTO commands(shares_change, symbol, price, transacted, id, remaining) VALUES(?, ?, ?, ?, ?, ?)", shares, data["symbol"], data["price"], data["time"], session["user_id"], remaining)
        else:
            check_cash = db.execute("SELECT remaining AS s FROM commands WHERE id = ? ORDER BY transacted DESC LIMIT 1", session["user_id"])
            if  check_cash[0]["s"] < this:
                return apology("Insufficient", 501)
            else:
                remaining = check_cash[0]["s"] - this
                db.execute("INSERT INTO commands(shares_change, symbol, price, transacted, id, remaining) VALUES(?, ?, ?, ?, ?, ?)", shares, data["symbol"], data["price"], data["time"], session["user_id"], remaining)

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    all_commands = db.execute("SELECT * FROM commands WHERE id = ?", session["user_id"])
    return render_template("history.html", commands=all_commands)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        if not "user_first_cash" in session:
            session["user_first_cash"] = rows[0]["cash"]


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
        if not request.form.get("query"):
            return apology("Missing symbol")

        data = lookup(request.form.get("query"))

        if data == None:
            return apology("Invalid symbol", 500)
        else:
            return render_template("quoted.html", data=data)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        if not request.form.get("username"):
            return apology("Must provide username", 403)
        username = request.form.get("username")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) >= 1:
            return apology("Please get another username", 401)

        elif not request.form.get("password"):
            return apology("Must provide password", 403)
        elif not request.form.get("repassword"):
            return apology("Must confirm password", 403)
        elif request.form.get("password") != request.form.get("repassword"):
            return apology("Passwords do not match", 403)
        else:
            hash = generate_password_hash(request.form.get("password"))
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)
            return redirect("/")
    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares_bf = request.form.get("shares")
        shares = int(shares_bf)

        if not symbol:
            return apology("Missing symbol")
        if not shares:
            return apology("Missing shares")

        user_command = db.execute("SELECT symbol, SUM(shares_change) AS s FROM commands WHERE id = ? AND symbol = ?", session["user_id"], symbol)

        if shares > user_command[0]["s"]:
            return apology("Too many shares", 504)

        data = lookup(symbol)

        if data == None:
            return apology("Invalid Symbol", 500)

        shares_sell = - shares

        this = data["price"] * shares_sell

        user_cash = db.execute("SELECT remaining FROM commands WHERE id = ? ORDER BY transacted DESC LIMIT 1", session["user_id"])

        remaining = user_cash[0]["remaining"] - this

        db.execute("INSERT INTO commands (shares_change, symbol, price, transacted, id, remaining) VALUES(?, ?, ?, ?, ?, ?)", shares_sell, data["symbol"], data["price"], data["time"], session["user_id"], remaining)

        return redirect("/")

    else:
        user_summary = db.execute("SELECT symbol, SUM(shares_change) AS t FROM commands WHERE id = ? GROUP BY symbol", session["user_id"])
        for i in range(len(user_summary)):
            if user_summary[i]["t"] == 0:
                user_summary.pop(i)

        return render_template("sell.html", user_summary=user_summary)


