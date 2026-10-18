🚀 PATH-BRUTER
⚡ A fast HTTP path discovery tool written in Go.
🔎 PATH-BRUTER is a command-line tool for authorized web security testing. It checks candidate URL paths using a wordlist, analyzes HTTP status codes, identifies redirects and potentially protected paths, detects basic Web Application Firewall (WAF) indicators, and saves matching URLs to a file.
✨ FEATURES
⚡ Concurrent HTTP requests
📂 Custom wordlist support
🌐 HTTP status code classification
🛡️ Basic WAF detection
🔄 Redirect detection
🔍 Basic soft-404 filtering
💾 Automatic results saving to found.txt
📋 REQUIREMENTS
🐧 Linux
🐹 Go 1.21 or later
📦 Git
📝 A wordlist text file
🛠️ INSTALLATION
🔄 Update package lists
⌨️ Command:
sudo apt update
📦 Install Git and Go
⌨️ Command:
sudo apt install -y git golang-go
🔎 Check Go version
⌨️ Command:
go version
⚠️ Go 1.21 or later is required. If your version is older, install a newer version from https://go.dev/dl/
📥 DOWNLOAD THE TOOL
📂 Clone the repository
⌨️ Command:
git clone https://github.com/K52-ai/path-bruter.git
📁 Enter the project directory
⌨️ Command:
cd path-bruter
📦 Download dependencies
⌨️ Command:
go mod download
⚙️ BUILD THE TOOL
🔨 Compile the program
⌨️ Command:
go build -o path-bruter main.go
🔑 Make the executable runnable
⌨️ Command:
chmod +x path-bruter
▶️ USAGE
🚀 Start PATH-BRUTER
⌨️ Command:
./path-bruter
🎯 Enter your authorized target URL when prompted
⌨️ Example:
https://example.com
📂 Enter your wordlist filename when prompted
⌨️ Example:
wordlist.txt
📝 CREATE A WORDLIST
📄 Create a wordlist file
⌨️ Command:
nano wordlist.txt
✍️ Add candidate paths, one per line
admin
login
api
robots.txt
sitemap.xml
💾 Save the file and exit the editor.
📊 RESULTS
🟢 OK — selected successful HTTP status codes
🔒 PROTECTED — HTTP 401 or 403
🔄 REDIRECT — HTTP redirect responses
📁 Results are saved to found.txt
👀 View results
⌨️ Command:
cat found.txt
🔢 Count saved entries
⌨️ Command:
wc -l found.txt
🖼️ SCREENSHOTS
🖥️ Tool Interface — assets/startup.png
🔍 Path Discovery — assets/scan-output.png
📊 Final Results — assets/results.png
📌 Upload your actual screenshots to the assets directory using the filenames above.
⚠️ IMPORTANT NOTES
🛡️ WAF detection uses basic signatures and may not identify every WAF.
🔍 Soft-404 filtering may produce inaccurate results.
🔐 TLS certificate verification is disabled in the current implementation.
⚡ Request concurrency is configured in the source code.
⚖️ RESPONSIBLE USE
☑ Use PATH-BRUTER only on systems you own or have explicit permission to test.
⚠️ Respect server rate limits and applicable laws.
📜 LICENSE
MIT License. See LICENSE for details.
👨‍💻 AUTHOR
🔥 K52-ai
🔗 GitHub: https://github.com/K52-ai/path-bruter
