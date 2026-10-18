🚀 PATH-BRUTER

⚡ A fast HTTP path discovery tool written in Go
PATH-BRUTER is a command-line tool for authorized web security testing. It checks candidate URL paths using a wordlist, analyzes HTTP status codes, detects basic WAF indicators, and saves matching URLs to a file.

✨ Features

* ⚡ Concurrent HTTP requests
* 📂 Custom wordlist support
* 🌐 HTTP status code classification
* 🛡️ Basic WAF detection
* 🔄 Redirect detection
* 🔍 Basic soft-404 filtering
* 💾 Saves results to found.txt

📋 Requirements

* 🐧 Linux
* 🐹 Go 1.21 or later
* 📦 Git
* 📝 A wordlist text file

🛠️ Installation

1. Update package lists

sudo apt update

2. Install Git and Go

sudo apt install -y git golang-go

3. Check your Go version

go version

Go 1.21 or later is required. If your version is older, install a newer version from https://go.dev/dl/
4. Clone the repository

git clone https://github.com/K52-ai/path-bruter.git

5. Enter the project directory

cd path-bruter

6. Download dependencies

go mod download

7. Build the tool

go build -o path-bruter main.go

8. Make it executable

chmod +x path-bruter

▶️ Usage

1. Start PATH-BRUTER

./path-bruter

2. Enter your authorized target URL when prompted
Example: https://example.com
3. Enter your wordlist filename when prompted
Example: wordlist.txt

📝 Create a Wordlist

Create a file:

nano wordlist.txt

Example contents:

admin
login
api
robots.txt
sitemap.xml

Save the file and exit the editor.

📊 Results

* 🟢 OK — selected successful HTTP status codes
* 🔒 PROTECTED — HTTP 401 or 403
* 🔄 REDIRECT — HTTP redirect responses
    Results are saved to found.txt.
    View results

cat found.txt

Count saved entries

wc -l found.txt

🖼️ Screenshots

Add your actual screenshots to the assets/ folder, then use:
⚠️ Important Notes

* 🛡️ WAF detection uses basic signatures and may not identify every WAF.
* 🔍 Soft-404 filtering may produce inaccurate results.
* 🔐 TLS certificate verification is disabled in the current implementation.
* ⚡ Request concurrency is configured in the source code.

⚖️ Responsible Use

Use PATH-BRUTER only on systems you own or have explicit permission to test. Respect server rate limits and applicable laws.

📜 License

MIT License. See LICENSE for details.

👨‍💻 Author

K52-ai
🔗 GitHub Repository

<img width="1365" height="579" alt="image" src="https://github.com/user-attachments/assets/c526a7cf-52c0-48a7-a51a-c9fd5780b2fb" />

