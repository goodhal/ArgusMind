# XSS Examples in Flask
# CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

from flask import Flask, request, render_template, render_template_string, Markup

app = Flask(__name__)

# =============== BAD EXAMPLE ===============
# UNSAFE: Rendering user input directly
@app.route('/bad')
def bad_xss():
    username = request.args.get('username', '')
    # Vulnerability: Direct string formatting in template string
    template = f"<h1>Welcome, {username}!</h1>"
    return render_template_string(template)  # XSS vulnerability!


# =============== GOOD EXAMPLE ===============
# SAFE: Use template variables (Flask auto-escapes)
@app.route('/good')
def good_xss():
    username = request.args.get('username', '')
    # Security: Flask's template engine auto-escapes variables
    return render_template('welcome.html', username=username)  # Safe!


# =============== BAD EXAMPLE 2 ===============
# UNSAFE: Using Markup with user input
@app.route('/bad-markup')
def bad_markup():
    content = request.args.get('content', '')
    # Vulnerability: Markup bypasses escaping
    return Markup(f"<div>{content}</div>")  # XSS vulnerability!


# =============== GOOD EXAMPLE 2 ===============
# SAFE: Sanitize before using Markup
from bleach import clean

@app.route('/good-markup')
def good_markup():
    content = request.args.get('content', '')
    # Security: Sanitize untrusted HTML
    sanitized_content = clean(content)
    return Markup(f"<div>{sanitized_content}</div>")  # Safe!
