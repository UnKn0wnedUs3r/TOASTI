from flask import (
    Flask,
    request,
    render_template,
    redirect,
    session
)

import re
import subprocess

app = Flask(__name__)
app.secret_key = "dev-only-change-me"


# ============================================================
# Prevent cache (CRITICAL)
# ============================================================

@app.after_request
def prevent_cache(response):

    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response


# ============================================================
# Login helper
# ============================================================

def require_login():

    return session.get("logged_in")


# ============================================================
# Math helper
# ============================================================

def _apply_op(a, op, b):

    if op == "*":
        return a * b

    if op == "+":
        return a + b

    if op == "-":
        return a - b

    return 0


# ============================================================
# Regex patterns
# ============================================================

RE_JINJA = re.compile(r"\{\{\s*(\d+)\s*([*+\-])\s*(\d+)\s*\}\}")
RE_FM_ARITH = re.compile(r"\$\{\s*(\d+)\s*([*+\-])\s*(\d+)\s*\}")
RE_FM_UPPER = re.compile(r'\$\{\s*"([^"]+)"\?upper_case\s*\}')
RE_FM_CONCAT = re.compile(r'\$\{\s*"([^"]+)"\s*\+\s*"([^"]+)"\s*\}')
RE_VEL = re.compile(r'#set\(\$([a-zA-Z]+)\s*=\s*(\d+)\s*([*+\-])\s*(\d+)\)(.*?)\$\1')
RE_MUS_IF = re.compile(r"\{\{#if\s+1\}\}(.+?)\{\{/if\}\}")
RE_MUS_UNLESS = re.compile(r"\{\{#unless\s+false\}\}(.+?)\{\{/unless\}\}")
RE_MUS_WITH = re.compile(r"\{\{#with\s+'([^']+)'\}\}\{\{this\}\}\{\{/with\}\}")


# ============================================================
# SSTI evaluators
# ============================================================

def eval_jinja(payload):

    return RE_JINJA.sub(

        lambda m: str(
            _apply_op(
                int(m.group(1)),
                m.group(2),
                int(m.group(3))
            )
        ),

        payload
    )


def eval_freemarker(payload):

    payload = RE_FM_ARITH.sub(
        lambda m: str(
            _apply_op(
                int(m.group(1)),
                m.group(2),
                int(m.group(3))
            )
        ),
        payload
    )

    payload = RE_FM_UPPER.sub(
        lambda m: m.group(1).upper(),
        payload
    )

    payload = RE_FM_CONCAT.sub(
        lambda m: m.group(1) + m.group(2),
        payload
    )

    return payload


def eval_velocity(payload):

    def sub(m):

        result = _apply_op(
            int(m.group(2)),
            m.group(3),
            int(m.group(4))
        )

        return m.group(5) + str(result)

    return RE_VEL.sub(sub, payload)


def eval_mustache(payload):

    payload = RE_MUS_IF.sub(lambda m: m.group(1), payload)
    payload = RE_MUS_UNLESS.sub(lambda m: m.group(1), payload)
    payload = RE_MUS_WITH.sub(lambda m: m.group(1), payload)

    return payload


# ============================================================
# PUBLIC ROUTES
# ============================================================

@app.route("/")
def index():

    breads = [
        {"name": "Sourdough", "price": 6.50},
        {"name": "Baguette", "price": 3.40},
        {"name": "Brioche", "price": 7.20}
    ]

    return render_template(

        "index.html",

        breads=breads,

        logged_in=session.get("logged_in"),

        username=session.get("username")

    )


@app.route("/search")
def search():

    q = request.args.get("q", "")
    category = request.args.get("category", "")

    return render_template(
        "search.html",
        q=q,
        category=category
    )


@app.route("/submit", methods=["GET","POST"])
def submit():

    name=""
    message=""
    bread=""
    rating=""

    if request.method=="POST":

        name=request.form.get("name","")
        message=request.form.get("message","")
        bread=request.form.get("bread","")
        rating=request.form.get("rating","")

    return render_template(
        "submit.html",
        name=name,
        message=message,
        bread=bread,
        rating=rating
    )


# ============================================================
# LOGIN / LOGOUT
# ============================================================

@app.route("/login", methods=["GET","POST"])
def login():

    if request.method=="POST":

        u=request.form.get("username")
        p=request.form.get("password")

        if u=="admin" and p=="admin123":

            session["logged_in"]=True
            session["username"]=u

            return redirect("/dashboard")

        return render_template("login.html", error="Invalid login")

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if not require_login():
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# ============================================================
# OS Injection 
# ============================================================

@app.route("/os")
def os_page():

    if not require_login():
        return redirect("/login")

    host = request.args.get("cmd", "")

    try:

        command = f"ping -n 1 {host}"

        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )

        output = result.stdout + result.stderr

    except Exception as e:

        output = str(e)

    return render_template(

        "engine.html",

        engine="OS Command Injection",

        field="cmd",

        payload=host,

        output=output

    )


# ============================================================
# Blind OS Injection 
# ============================================================

@app.route("/blind_os")
def blind_os_page():

    if not require_login():
        return redirect("/login")

    host = request.args.get("cmd", "")

    try:

        if host:

            command = f"ping -c 1 {host}"

            # Execute exactly like normal OS injection
            subprocess.run(
                command,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

    except:
        pass

    # Always return same response (blind behavior)

    return render_template(

        "engine.html",

        engine="Blind OS Command Injection",

        field="cmd",

        payload=host,

        output="Command executed."

    )

# ============================================================
# SSTI ROUTES (PROTECTED)
# ============================================================

@app.route("/ssti")
def ssti():

    if not require_login():
        return redirect("/login")

    payload=request.args.get("input","")

    output=eval_jinja(payload)

    return render_template(
        "engine.html",
        engine="Jinja2",
        field="input",
        payload=payload,
        output=output
    )


@app.route("/twig")
def twig():

    if not require_login():
        return redirect("/login")

    payload=request.args.get("input","")

    output=eval_jinja(payload)

    return render_template(
        "engine.html",
        engine="Twig",
        field="input",
        payload=payload,
        output=output
    )


@app.route("/freemarker")
def freemarker():

    if not require_login():
        return redirect("/login")

    payload=request.args.get("input","")

    output=eval_freemarker(payload)

    return render_template(
        "engine.html",
        engine="FreeMarker",
        field="input",
        payload=payload,
        output=output
    )


@app.route("/velocity")
def velocity():

    if not require_login():
        return redirect("/login")

    payload=request.args.get("input","")

    output=eval_velocity(payload)

    return render_template(
        "engine.html",
        engine="Velocity",
        field="input",
        payload=payload,
        output=output
    )


@app.route("/mustache")
def mustache():

    if not require_login():
        return redirect("/login")

    payload=request.args.get("input","")

    output=eval_mustache(payload)

    return render_template(
        "engine.html",
        engine="Mustache",
        field="input",
        payload=payload,
        output=output
    )


# ============================================================

if __name__=="__main__":

    app.run(debug=True)
