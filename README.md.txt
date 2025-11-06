💼 SuiWallet — Multi-Network Web Wallet (Testnet / Mainnet / Devnet)

SuiWallet is a secure and modern web wallet for the Sui blockchain, built with Flask, PySui, and a responsive HTML/JS frontend  
It supports:
- 🔐 User login/signup via password hash  
- 🔑 Secure wallet generation & recovery using 12-word seed phrase  
- 🔄 Multi-network support (Testnet, Devnet, Mainnet)  
- 💸 Sending & receiving SUI  
- 📜 Transaction history tracking  
- 🪶 Clean responsive UI with network notifications  
- 🐳 Dockerized for simple deployment  


🚀 Features

- Multi-Network Toggle — Switch between Mainnet, Testnet, and Devnet easily from the frontend.  
- 12-Word Seed Phrase Recovery — Recover existing wallets securely.  
- End-to-End Encryption — Private keys encrypted with Fernet & JWT-based authentication.  
- Modern UI — Clean responsive HTML/JS interface served directly by Flask.  
- Blockchain Integration — Uses latest [`pysui`](https://pypi.org/project/pysui/) to interact with the Sui blockchain.


 🏗️ Tech Stack

  Layer            Technology 

  Backend          Python 3.11+, Flask, SQLAlchemy, PySui, JWT 
  Frontend         HTML5, JavaScript (Fetch API), TailwindCSS 
  Database         SQLite (can easily upgrade to PostgreSQL/MySQL) 
  Containerization Docker + docker-compose 
  Security         Fernet Encryption, JWT Authentication 


⚙️ Installation (Local Setup)

1️⃣ Clone the Repository
 bash
 git clone https://github.com/YOUR_USERNAME/suiwallet.git
 cd suiwallet
