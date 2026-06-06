// Path Traversal Examples
// CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

const express = require('express');
const path = require('path');
const app = express();

// =============== BAD EXAMPLE ===============
// UNSAFE: Direct use of user input in file path
app.get('/download', (req, res) => {
    const filename = req.query.file;
    // Vulnerability: User input directly used as file path
    res.sendFile(filename);
    // If filename = "../../etc/passwd", it exposes sensitive files!
});

// =============== GOOD EXAMPLE ===============
// SAFE: Validate and sanitize file path
app.get('/safe-download', (req, res) => {
    const filename = req.query.file;
    
    // Security: Define a safe base directory
    const baseDir = path.join(__dirname, 'public');
    
    // Security: Join and resolve path
    const fullPath = path.resolve(baseDir, filename);
    
    // Security: Verify path is within base directory
    if (!fullPath.startsWith(baseDir)) {
        return res.status(403).send('Access denied');
    }
    
    res.sendFile(fullPath);
});

// =============== BETTER EXAMPLE ===============
// SAFER: Use allowlist for valid files
const allowedFiles = ['readme.txt', 'data.json', 'info.html'];

app.get('/better-download', (req, res) => {
    const filename = req.query.file;
    
    // Security: Check against allowlist
    if (!allowedFiles.includes(filename)) {
        return res.status(404).send('File not found');
    }
    
    res.sendFile(path.join(__dirname, 'public', filename));
});
