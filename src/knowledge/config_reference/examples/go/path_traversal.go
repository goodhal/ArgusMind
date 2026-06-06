// Path Traversal Examples
// CWE-022: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

package main

import (
	"net/http"
	"path/filepath"
)

// =============== BAD EXAMPLE ===============
// UNSAFE: Direct use of user input in file path
func badServeFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// Vulnerability: User input directly used as file path
	http.ServeFile(w, r, filename)
	// If filename = "../../etc/passwd", it exposes sensitive files!
}

// =============== GOOD EXAMPLE ===============
// SAFE: Validate and sanitize file path
func goodServeFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	
	// Security: Define a safe base directory
	baseDir := "./public/"
	
	// Security: Join and clean path
	fullPath := filepath.Join(baseDir, filename)
	
	// Security: Verify path is within base directory
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	
	// Security: Ensure path is under base directory
	if len(absPath) < len(absBase) || absPath[:len(absBase)] != absBase {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	http.ServeFile(w, r, absPath)
}

// =============== BETTER EXAMPLE ===============
// SAFER: Use allowlist for valid files
var allowedFiles = map[string]bool{
	"readme.txt": true,
	"data.json":  true,
	"info.html":  true,
}

func betterServeFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	
	// Security: Check against allowlist
	if !allowedFiles[filename] {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	http.ServeFile(w, r, "./public/"+filename)
}
