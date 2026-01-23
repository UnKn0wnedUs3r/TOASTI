from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.get("/")
def home():
    return """
    <h1>SSTI Test Lab (Flask/Jinja2) - POST Variant</h1>
    <p>Use the forms below, or POST directly with curl.</p>

    <h2>1) Vulnerable: Message Preview</h2>
    <form action="/preview" method="POST">
      <label>Message:</label><br>
      <textarea name="msg" rows="4" cols="60">Hello {{7*7}}</textarea><br><br>
      <button type="submit">Preview (Vulnerable)</button>
    </form>

    <h2>2) Safe: Message Preview</h2>
    <form action="/preview_safe" method="POST">
      <label>Message:</label><br>
      <textarea name="msg" rows="4" cols="60">Hello {{7*7}}</textarea><br><br>
      <button type="submit">Preview (Safe)</button>
    </form>

    <hr>
    <h3>Automation endpoints</h3>
    <ul>
      <li><code>POST /api/preview</code> (vulnerable)</li>
      <li><code>POST /api/preview_safe</code> (safe control)</li>
    </ul>
    """

# -------------------------
# VULNERABLE (POST form)
# -------------------------
# User input is inserted into the TEMPLATE SOURCE and then rendered.
@app.post("/preview")
def preview():
    msg = request.form.get("msg", "")

    template = f"""
    <h2>Preview (Vulnerable)</h2>
    <p><small>Input is compiled as template source.</small></p>
    <div style="padding:12px;border:1px solid #ccc;white-space:pre-wrap;">
      {msg}
    </div>
    <hr>
    <a href="/">Back</a>
    """
    return render_template_string(template)

# -------------------------
# SAFE (POST form)
# -------------------------
# User input is passed as DATA to a fixed template.
@app.post("/preview_safe")
def preview_safe():
    msg = request.form.get("msg", "")

    template = """
    <h2>Preview (Safe)</h2>
    <p><small>Input is data, not template source.</small></p>
    <div style="padding:12px;border:1px solid #ccc;white-space:pre-wrap;">
      {{ msg }}
    </div>
    <hr>
    <a href="/">Back</a>
    """
    return render_template_string(template, msg=msg)

# -------------------------
# VULNERABLE (API)
# -------------------------
# Supports both form-encoded and JSON for easy scanner integration.
@app.post("/api/preview")
def api_preview():
    msg = ""
    if request.is_json:
        msg = (request.get_json(silent=True) or {}).get("msg", "")
    else:
        msg = request.form.get("msg", "")

    template = f"API Preview (Vulnerable): {msg}"
    return render_template_string(template), 200, {"Content-Type": "text/plain; charset=utf-8"}

# evaluate by
# curl -s -X POST http://127.0.0.1:5000/api/preview \
#   -H "Content-Type: application/json" \
#   -d '{"msg":"{{7*7}}"}'

# -------------------------
# SAFE (API CONTROL)
# -------------------------
@app.post("/api/preview_safe")
def api_preview_safe():
    msg = ""
    if request.is_json:
        msg = (request.get_json(silent=True) or {}).get("msg", "")
    else:
        msg = request.form.get("msg", "")

    template = "API Preview (Safe): {{ msg }}"
    return render_template_string(template, msg=msg), 200, {"Content-Type": "text/plain; charset=utf-8"}

if __name__ == "__main__":
    # localhost only
    app.run(host="127.0.0.1", port=5000, debug=True)
