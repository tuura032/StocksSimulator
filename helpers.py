import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Contact API
    try:
        response = requests.get(f"https://api.iextrading.com/1.0/stock/{urllib.parse.quote_plus(symbol)}/quote")
        response.raise_for_status()
    except requests.RequestException:
        return None

    # Parse response
    try:
        quote = response.json()
        return {
            "name": quote["companyName"],
            "price": float(quote["latestPrice"]),
            "symbol": quote["symbol"]
        }
    except (KeyError, TypeError, ValueError):
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"

def cccheck(ccn):
    """Check if CC number is valid"""

    cccopy = ccn
    cc = ccn

    # CC number minus last digit
    nolast = cc//10

    # Set Counter to 2nd to last digit, possibly x2
    initialcounter = ((nolast%10)*2)

    if initialcounter > 9:
        counter = (initialcounter%10)+1
    else:
        counter = initialcounter

    # Add Together every other digit from cc, possibly x2
    while True:
        if nolast == 0:
            break
        nolast = nolast//100
        k = ((nolast%10)*2)
        if k > 9:
            k = (k%10)+1
        for x in range(k):
            counter += 1

    # Add together all remaining digits from cc
    counter2 = cc % 10
    while True:
        if cccopy == 0:
            break
        cccopy = cccopy//100
        m = cccopy % 10
        for y in range(m):
            counter2 += 1

    # Add Values together in Checksum
    sum1 = counter + counter2

    # Determine which card type if valid
    if ((sum1 % 10) > 0) or ((sum1 % 10) < 0):
        return False
    else:
        if (cc // 1000000000000) == 4 or (cc // 1000000000000000) == 4:
            return True
        elif (cc // 10000000000000) == 34 or (cc // 10000000000000) == 37:
            return True
        elif (cc // 100000000000000) > 50 and (cc // 100000000000000) < 56:
            return True
        else:
            return False