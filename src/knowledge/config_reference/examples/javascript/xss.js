// XSS (Cross-Site Scripting) Examples
// CWE-079: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

// =============== BAD EXAMPLE ===============
// UNSAFE: Directly inserting user input into HTML
function badXSS(username) {
    // Vulnerability: User input directly inserted into DOM
    document.getElementById('welcome').innerHTML = `Welcome, ${username}!`;
    // If username = '<script>alert("XSS")</script>', it will execute!
}


// =============== GOOD EXAMPLE ===============
// SAFE: Use textContent instead of innerHTML
function goodXSS(username) {
    // Security: Text content is automatically escaped
    document.getElementById('welcome').textContent = `Welcome, ${username}!`;
    // Script tags are treated as plain text
}


// =============== REACT EXAMPLE ===============
// SAFE: React automatically escapes values
function Welcome({ username }) {
    // Security: React escapes by default
    return <div>Welcome, {username}</div>;
}

// UNSAFE: Using dangerouslySetInnerHTML without sanitization
function UnsafeWelcome({ content }) {
    // Vulnerability: Direct HTML insertion
    return <div dangerouslySetInnerHTML={{ __html: content }} />;
}

// SAFE: Sanitize before using dangerouslySetInnerHTML
import DOMPurify from 'dompurify';

function SafeWelcome({ content }) {
    // Security: Sanitize untrusted HTML
    const sanitizedContent = DOMPurify.sanitize(content);
    return <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />;
}
