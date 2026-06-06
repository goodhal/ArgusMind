# SQL Injection Examples
# CWE-089: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

# =============== BAD EXAMPLE ===============
# UNSAFE: String concatenation with user input
def bad_sql_query(request):
    import sqlite3
    user_id = request.GET.get('id')
    
    # Vulnerability: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect('mydb.db')
    cursor = conn.cursor()
    cursor.execute(query)  # SQL Injection!


# =============== GOOD EXAMPLE ===============
# SAFE: Use parameterized queries
def good_sql_query(request):
    import sqlite3
    user_id = request.GET.get('id')
    
    # Security: Parameterized query with placeholders
    query = "SELECT * FROM users WHERE id = ?"
    conn = sqlite3.connect('mydb.db')
    cursor = conn.cursor()
    cursor.execute(query, (user_id,))  # Safe!


# =============== DJANGO EXAMPLE ===============
# SAFE: Django ORM automatically uses parameterized queries
def django_orm_example(request):
    from myapp.models import User
    
    user_id = request.GET.get('id')
    
    # Security: Django ORM protects against SQL injection
    users = User.objects.filter(id=user_id)  # Safe!
    
    # UNSAFE: Raw queries without parameters
    # users = User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")  # Vulnerable!
    
    # SAFE: Raw queries with parameters
    users = User.objects.raw('SELECT * FROM users WHERE id = %s', [user_id])  # Safe!
