import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
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
    portfolio = db.execute(
        "SELECT stock_symbol, shares_count FROM portfolio WHERE user_id = ?", session["user_id"])

    portfolio_value = 0
    for stock in portfolio:
        stock["stock_price"] = lookup(stock["stock_symbol"])["price"]
        portfolio_value += stock["shares_count"] * stock["stock_price"]

    cash_value = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash_value = cash_value[0]["cash"]

    return render_template("index.html", portfolio=portfolio, portfolio_value=portfolio_value, cash_value=cash_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":

        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol")
        if not lookup(symbol):
            return apology("something went wrong, make sure to provide a valid symbol")
        stock_details = lookup(symbol)

        shares = request.form.get("shares")
        if not shares:
            return apology("must provide shares")
        if not shares.isdigit():
            return apology("no of shares must be numeric")
        if int(shares) <= 0:
            return apology("you need to buy more than 0 shares")

        shares = int(shares)
        purchase_amt = stock_details["price"] * shares

        user_balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        user_balance = user_balance[0]["cash"]

        if user_balance < purchase_amt:
            return apology("Sorry, you don't have enough balance")

        existing_stock = db.execute(
            "SELECT shares_count FROM portfolio WHERE stock_symbol = ? AND user_id = ?", symbol, session["user_id"])

        if existing_stock:
            current_shares = existing_stock[0]["shares_count"]
            db.execute("UPDATE portfolio SET shares_count = ? WHERE stock_symbol = ? AND user_id = ?",
                       current_shares + shares, symbol, session["user_id"])
        else:
            db.execute("INSERT INTO portfolio (user_id, stock_symbol, shares_count) VALUES (?, ?, ?)",
                       session["user_id"], symbol, shares)

        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   user_balance - purchase_amt, session["user_id"])

        # add transaction
        db.execute("INSERT INTO transactions (user_id, type, stock_symbol, stock_price, shares_count) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], "BUY", symbol, stock_details["price"], shares)

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT type, stock_symbol, stock_price, shares_count, datetime FROM transactions WHERE user_id = ?", session["user_id"])
    return render_template("history.html", transactions=transactions)


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
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol")
        if lookup(symbol) is None:
            return apology("make sure to provide a valid symbol")

        stock_details = lookup(symbol)
        return render_template("quoted.html", name=stock_details["name"], price=stock_details["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # Error Checking
        if not username:
            return apology("must provide username")
        elif not password:
            return apology("must provide password")
        elif not request.form.get("confirmation"):
            return apology("must enter your password again")
        elif password != request.form.get("confirmation"):
            return apology("password does not match")

        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                       username, generate_password_hash(password))
        except ValueError:
            return apology("username already taken")
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must choose a symbol")

        shares_count = db.execute(
            "SELECT shares_count FROM portfolio WHERE user_id = ? AND stock_symbol = ?", session["user_id"], symbol)
        shares_count = shares_count[0]["shares_count"]
        if shares_count <= 0:
            return apology("Sorry, but you don't own any shares of the stock")

        shares_sell = request.form.get("shares")
        if not shares_sell.isdigit():
            return apology("no of shares must be numeric")
        shares_sell = int(shares_sell)
        if shares_sell <= 0:
            return apology("You need to sell at least 1 share")
        if shares_count < shares_sell:
            return apology("You don't own enough shares")

        if shares_count == shares_sell:
            db.execute("DELETE FROM portfolio WHERE stock_symbol = ? AND user_id = ?",
                       symbol, session["user_id"])
        else:
            db.execute("UPDATE portfolio SET shares_count = ? WHERE stock_symbol = ? AND user_id = ?",
                       shares_count - shares_sell, symbol, session["user_id"])

        stock_price = lookup(symbol)["price"]
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        balance = balance[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", balance +
                   (stock_price * shares_sell), session["user_id"])

        # ADD transaction
        db.execute("INSERT INTO transactions (user_id, type, stock_symbol, stock_price, shares_count) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], "SELL", symbol, stock_price, shares_sell)

        return redirect("/")
    else:
        portfolio = db.execute(
            "SELECT stock_symbol, shares_count FROM portfolio WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", portfolio=portfolio)
