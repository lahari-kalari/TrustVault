\# TrustVault — Secure Document Management System



TrustVault is a web-based document management application built with Python and Flask. It provides user authentication, role-based access control, document uploading, document search, and secure document sharing.



\## Features



\- \*\*User Authentication:\*\* User registration, login, and logout.

\- \*\*Role-Based Access Control:\*\* Access permissions based on user roles.

\- \*\*Document Upload:\*\* Upload supported documents such as PDF, PNG, JPG, JPEG, TXT, and DOCX.

\- \*\*Document Search:\*\* Find documents using the search functionality.

\- \*\*Document Sharing:\*\* Share documents with authorized users.

\- \*\*Access Revocation:\*\* Revoke previously granted document access.

\- \*\*Security Protections:\*\* Password hashing and CSRF protection.



\## Technologies Used



\- Python

\- Flask

\- Flask-Login

\- Flask-WTF

\- SQLAlchemy

\- SQLite

\- HTML and CSS

\- Git and GitHub



\## Installation and Setup



\### 1. Clone the repository



```bash

git clone https://github.com/lahari-kalari/TrustVault.git

cd TrustVault

```



\### 2. Create a virtual environment



```bash

python -m venv .venv

```



\### 3. Activate the virtual environment



\*\*Windows PowerShell:\*\*



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



\### 4. Install dependencies



If a `requirements.txt` file is available:



```bash

pip install -r requirements.txt

```



\### 5. Configure environment variables



Create a local `.env` file or configure the environment variables required by the application. Use a strong, unique secret key. Never commit credentials, database files, or private uploads to GitHub.



\### 6. Run the application



Follow the application's configuration requirements, then run its Flask entry point. For example, if the entry point is `app.py`:



```bash

python app.py

```



Open the local address shown in the terminal in your browser.



\## Security Notes



\- Passwords should be stored using secure password hashing.

\- Access to documents should be checked on the server for every request.

\- Secret keys and credentials must remain private.

\- Local databases, uploaded documents, and virtual environments should not be committed to Git.



\## Future Enhancements



\- Automated testing and continuous integration.

\- Improved document previews.

\- Audit logs for document access and sharing.

\- Enhanced administrative dashboard.



\## Author



\*\*K. Lahari\*\*



Final-Year Computer Science Student (AI \& ML)



GitHub: https://github.com/lahari-kalari



