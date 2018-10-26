import os

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
import requests

from helpers import apology, login_required, lookup, usd, cccheck

# Configure application
app = Flask(__name__)

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine('postgres://mglgirwhnmxdjs:fd8813a60d2b0945159408499f192e2062b54753825d83323f04d3c5f2c0a042@ec2-54-83-19-244.compute-1.amazonaws.com:5432/d4q7kt3q4lq9ni')
db = scoped_session(sessionmaker(bind=engine))

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route("/home")
def home():
    return render_template("login.html")

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Select the users available cash, and entire portfolio
    tables = db.execute("SELECT * FROM portfolio WHERE id = :id", id=session["user_id"]).fetchall()
    cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"]).fetchall()
    networth = cash[0]["cash"]

    # for each row in tables, pull out the symbol and update the current stock price, and and get current value of all stocks
    for table in tables:
        symbol = table["symbol"]
        shares = table["shares"]
        quote = lookup(symbol)
        newprice = quote["price"]
        newtotal = newprice * shares
        networth += newtotal
        db.execute("UPDATE portfolio SET price = :price, total = :total WHERE id = :id AND symbol =:symbol", \
                    price = usd(quote["price"]), total = usd(newtotal), id = session["user_id"], symbol=symbol)
        db.commit()

    # Update table
    upd_tables = db.execute("SELECT * FROM portfolio WHERE id = :id", id=session["user_id"]).fetchall()

    # Once prices and total stock value is updated, send it to the rendered template
    return render_template("index.html", tables=upd_tables, money = usd(cash[0]["cash"]), networth = usd(networth))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        # Get user input, and lookup a quote of the input stock
        if not request.form.get("symbol"):
            return apology("I already checked for this elsewhere", 400)

        ticker = request.form.get("symbol").upper()
        quote = lookup(ticker)
        shares = request.form.get("shares")

        # Ensure proper quantity was submitted
        if shares.isnumeric() == True and int(shares) > 0:
            shares = int(request.form.get("shares"))
        else:
            return apology("Must Enter Valid Quantity", 400)

        # Ensure proper symbol was submitted
        if not ticker or not quote or ticker.isalpha() == False or len(ticker) > 5:
            return apology("must enter valid ticker symbol", 400)

        # Query database for user's cash
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])

        # Determine total purchase cost
        cost = float(shares) * (quote["price"])

        # Execute the transaction if funds are adequate
        if float(cash[0]["cash"]) > cost:

            # create new transaction log
            db.execute("INSERT INTO transactions (ticker, price, quantity, id) \
                            VALUES (:stockpurchase, :price, :quantity, :id)", \
                            stockpurchase=ticker, \
                            price=usd(quote["price"]), \
                            quantity=shares, \
                            id=session['user_id'])

            # update remaining cash
            db.execute("UPDATE users SET cash = cash - :cost WHERE id = :id", \
                            cost = cost, \
                            id = session['user_id'])

            # Select total shares of a single stock from users portfolio
            totalstock = db.execute("SELECT shares FROM portfolio \
                                        WHERE id = :id AND symbol= :symbol", \
                                        id=session["user_id"], symbol=quote["symbol"])

            # If user has no shares of stock, insert it into portfolio
            if not totalstock:
                db.execute("INSERT INTO portfolio (name, shares, price, total, symbol, id) \
                            VALUES (:name, :shares, :price, :total, :symbol, :id)", \
                            name=quote["name"], shares=shares, price=usd(quote["price"]), \
                            total=(usd(quote["price"]*shares)), symbol=quote["symbol"] , id=session['user_id'])

            # If user has prior shares, update their total number of shares
            else:
                db.execute("UPDATE portfolio SET shares = :shares WHERE id =:id AND symbol = :symbol", \
                            shares = shares+(totalstock[0]["shares"]), id=session["user_id"], symbol=quote["symbol"])

            flash('You rock, you bought some stocks!')

            # Return user to "buy" page
            # Update table
            upd_tables = db.execute("SELECT * FROM portfolio WHERE id = :id", id=session["user_id"])
            cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
            return render_template("index.html", tables = upd_tables, money = usd(cash[0]["cash"]))

        else:
            return apology("not enough money", 403)

    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get all of the transactions
    history = db.execute("SELECT * FROM transactions WHERE id = :id", id = session["user_id"])

    # Return transactions to web page
    return render_template("history.html", history = history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username l", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users2 WHERE username = :username",
                          {'username':request.form.get("username")})

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Incorrect Username and/or Password - Try Again")
            return render_template("login.html")

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

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        quote = lookup(request.form.get("symbol"))

        if not quote:
            flash("Invalid Ticker")
            return apology("must enter valid ticker", 400)

        return render_template("stockinfo.html", name=quote['name'], symbol=quote['symbol'], price=usd(quote['price']))

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must Provide a Username")
            return apology("Must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password") or not request.form.get("confirmation"):
            flash("Must Provide Password")
            return apology("Must provide password", 400)

        # Ensure passwords match and meet length requirement
        elif not request.form.get("password") == request.form.get("confirmation") or len(request.form.get("password")) < 8:
            flash("Password must be longer than 8 characters.")
            return apology("Passwords must match and be 8 or more characters", 400)

        # Create new account
        result = db.execute("INSERT INTO users2 (username, hash) VALUES (:username, :hash)", {'username':request.form.get("username"), 'hash':generate_password_hash(request.form.get("password"))})
        db.commit()

        if not result:
            return apology("This username is already taken, please try again!", 400)

        # Save login
        session["user_id"] = result

        flash("Registration Successful!")

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Get user input, and lookup a quote of the input stock
        ticker = request.form.get("symbol")
        sharessold = int(request.form.get("shares"))
        quote = lookup(ticker)
        totalsold = quote["price"]*sharessold

        # Get user information from database
        sharesowned = db.execute("SELECT shares FROM portfolio WHERE id = :id AND symbol = :symbol", \
                                        id=session["user_id"], symbol = ticker)

        # Ensure symbol was submitted
        if not ticker:
            return apology("must enter proper ticker symbol", 400)

        # Ensure quantity of shares was submitted
        elif not sharessold or int(sharessold) < 1:
            return apology("must provide valid quantity", 400)

        # Check if user owns shares of that company
        elif not sharesowned:
            return apology("you don't own shares of this stock", 400)

        # Check if user has enough shares of that company
        elif sharesowned[0]["shares"] < sharessold:
            return apology("you don't enough shares of this stock", 400)

        # update user cash (current price * shares)
        db.execute("UPDATE users SET cash=cash+:sold WHERE id = :id", \
                        sold = float(totalsold), \
                        id = session['user_id'])

        if sharesowned[0]["shares"] == sharessold:
            db.execute("DELETE FROM portfolio WHERE id=:id AND symbol=:symbol", \
                            id=session["user_id"], symbol=ticker.upper())

        else:
            # Update portfolio to reflect the new number of shares
            db.execute("UPDATE portfolio SET shares = shares-:quantity WHERE id = :id AND symbol = :symbol", \
                            quantity = sharessold, id=session["user_id"], symbol = ticker.upper())

        # add a negative transaction to transaction log
        db.execute("INSERT INTO transactions (ticker, price, quantity, id) \
                            VALUES (:stocksell, :price, :quantity, :id)", \
                            stocksell=ticker.upper(), \
                            price=usd(quote["price"]), \
                            quantity= -sharessold, \
                            id=session['user_id'])

        flash('You Sold Some Stocks!')

        return redirect("/")
    else:
        seq = db.execute("SELECT symbol FROM portfolio WHERE id=:id", id=session["user_id"])
        return render_template("sell.html", seq = seq)

@app.route("/myaccount", methods=["GET", "POST"])
@login_required
def myaccount():
    """Update user settings"""

    return render_template("myaccount.html")

@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    """Update user settings"""

    # User reached route via POST
    if request.method == "POST":

        # Ensure password was submitted
        if not request.form.get("oldpassword"):
            return apology("must provide password", 403)

        # Get the old password from user, and compare it to stored hash
        oldpw = request.form.get("oldpassword")
        pwhash = db.execute("SELECT hash FROM users WHERE id=:id", \
                                id=session["user_id"])

        if check_password_hash(pwhash[0]["hash"], oldpw) == False:
            return apology("Password is incorrect, try again", 403)

        # Make sure new password is confirmed and meets length requirements
        elif not request.form.get("newpassword") == request.form.get("confirmnewpassword"):
            return apology("New passwords must match", 403)

        elif len(request.form.get("newpassword")) < 8:
            flash("Password must contain 8 or more characters")
            return render_template("myaccount.html")

        # Change the password hash
        db.execute("UPDATE users SET hash = :hash WHERE id = :id", \
                    hash = generate_password_hash(request.form.get("newpassword")), \
                    id=session["user_id"])

        flash("Password Changed Successfully!")

        return redirect("/")

    else:
        return render_template("changepassword.html")

@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("deposit.html")

    # User reached route via POST (as by submitting a form via POST)
    elif request.method == "POST":
        if not request.form.get("deposit"):
            return apology("must provide amount", 403)

        # Check if user has entered valid CC information
        check = db.execute("SELECT ccn FROM pymntinfo WHERE id=:id", id=session["user_id"])
        if not check:
            return apology("no payment information entered", 403)

        # If deposit is valid, update user cash
        deposit = request.form.get("deposit")
        if deposit.isnumeric() == True and int(deposit) > 0:
            db.execute("UPDATE users SET cash = cash + :newcash WHERE id=:id", \
                    newcash = float(deposit), id=session["user_id"])

        # Return error if amount is not valid
        else:
            flash("Enter a valid amount")
            return render_template("deposit.html")

        flash("Funds Successfully Added")
        return redirect("/")


@app.route("/payment", methods=["GET", "POST"])
@login_required
def payment():
    """Enter Payment Information"""

    if request.method == "POST":

        # Check if ccn is valid
        ccn = int(request.form.get("payment"))
        if cccheck(ccn) == False:
            flash("Something Went Wrong, Try Again")
            return render_template("payment.html")

        # Check if user already has a CC on file
        check = db.execute("SELECT ccn FROM pymntinfo WHERE id=:id", id=session["user_id"])
        if check:
            flash("cc already exists")
            return render_template("payment.html")

        # Add cc to users account if valid
        else:
            db.execute("INSERT INTO pymntinfo (id, ccn) VALUES (:id, :ccn)", \
                        id=session["user_id"], ccn=ccn)

        flash("Credit Card is Valid")
        return render_template("myaccount.html")

    else:
        return render_template("payment.html")

@app.route("/deletecc", methods=["GET"])
@login_required
def deletecc():
    """Deletes Payment Information"""

    # See if payment info already exists
    check = db.execute("SELECT ccn FROM pymntinfo WHERE id=:id", id=session["user_id"])

    # Delete it if it exists
    if check:
        db.execute("DELETE FROM pymntinfo WHERE id=:id", id=session["user_id"])
        flash("Payment Information Deleted")
    else:
        flash("No Card On File")
    return redirect("/")

def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
