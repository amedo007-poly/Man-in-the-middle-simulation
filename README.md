# 🔐 Man-in-the-Middle Attack Simulator

An interactive educational platform for understanding MITM (Man-in-the-Middle) attacks and cybersecurity concepts.

![Security Demo](https://img.shields.io/badge/Security-Educational-orange)
![License](https://img.shields.io/badge/License-Educational-blue)

## 🎯 Overview

This interactive web application demonstrates how Man-in-the-Middle attacks work in a safe, educational environment. It features beautiful animations, real-time packet visualization, and comprehensive learning materials about network security.

## ✨ Features

### 🎮 Interactive Simulation
- **Real-time Network Visualization**: Watch packets travel between Alice, Bob, and Eve (the attacker)
- **Multiple Attack Scenarios**: HTTP, HTTPS, ARP Spoofing, and DNS Spoofing demonstrations
- **Packet Interception**: See how attackers can capture, modify, or drop messages
- **Live Statistics**: Track messages sent, intercepted, modified, and protected

### 📚 Educational Content
- **Comprehensive Learning Tab**: Deep dive into MITM attack mechanics
- **Attack Stages Breakdown**: Understand interception, decryption, and exploitation phases
- **Interactive Quiz**: Test your knowledge with detailed explanations
- **Prevention Strategies**: Learn best practices to protect yourself

### 💻 Live Demonstrations
- **HTTP vs HTTPS Comparison**: See the difference encryption makes
- **Credential Capture Demo**: Understand why HTTPS is essential
- **Terminal Simulation**: Experience attacker tools in a safe environment
- **Security Checklist**: Track your security practices

## 🚀 Live Demo

Visit the live application: [MITM Simulator on Vercel](https://your-deployment-url.vercel.app)

## 📸 Screenshots

### Network Visualization
The main simulation shows real-time packet flow between entities:
- **Alice** (Client) - The victim sending data
- **Bob** (Server) - The intended recipient
- **Eve** (Attacker) - The malicious interceptor

### Security Scenarios
- 🌐 HTTP (Unencrypted) - Vulnerable to interception
- 🔒 HTTPS (Encrypted) - Protected with TLS
- 📡 ARP Spoofing - Network-level attack
- 🌍 DNS Spoofing - Domain hijacking

## 🛠️ Technology Stack

- **Frontend**: Pure HTML5, CSS3, JavaScript (Vanilla)
- **Styling**: Custom CSS with modern animations
- **Fonts**: Google Fonts (Raleway, Playfair Display, Roboto Mono)
- **Icons**: Font Awesome 6.4.0
- **Deployment**: Vercel

## 📦 Project Structure

```
.
├── index (4).html          # Main interactive simulation
├── MITM.html              # Alternative React-based simulator
├── MITM_Presentation.tex  # LaTeX Beamer presentation
└── README.md              # This file
```

## 🎓 Educational Use Cases

This simulator is perfect for:
- **Cybersecurity Courses**: Demonstrate attack concepts visually
- **Security Awareness Training**: Show employees real threats
- **Student Projects**: Learn about network security interactively
- **Self-Learning**: Understand MITM attacks at your own pace

## 🔒 Security & Ethics

**⚠️ IMPORTANT NOTICE ⚠️**

This application is designed **SOLELY FOR EDUCATIONAL PURPOSES**. 

- ✅ Use it to learn about security vulnerabilities
- ✅ Use it to teach others about cyber threats
- ✅ Use it to understand how to protect yourself
- ❌ **NEVER** use these techniques against real systems without authorization
- ❌ Unauthorized interception is **ILLEGAL** and unethical

**Disclaimer**: The creators are not responsible for any misuse of this educational material.

## 🚀 Deployment

### Deploy to Vercel (Recommended)

1. **Push to GitHub**:
   ```bash
   git add .
   git commit -m "Initial commit"
   git push origin main
   ```

2. **Connect to Vercel**:
   - Visit [vercel.com](https://vercel.com)
   - Sign in with GitHub
   - Click "Import Project"
   - Select your repository
   - Click "Deploy"

### Local Development

Simply open `index (4).html` in a modern web browser:

```bash
# Option 1: Direct file open
open index\ (4).html

# Option 2: Local server (recommended)
python -m http.server 8000
# Then visit http://localhost:8000
```

## 📖 How to Use

1. **Choose a Tab**: Navigate between Simulation, Demo, Terminal, Learn, Quiz, and Prevention
2. **Select a Scenario**: Pick HTTP, HTTPS, ARP Spoofing, or DNS Spoofing
3. **Enable the Attacker**: Toggle Eve to intercept communications
4. **Send Messages**: Watch how packets flow through the network
5. **Learn & Practice**: Take the quiz and review prevention strategies

## 🎨 Features Breakdown

### Simulation Tab
- Network topology visualization
- Real-time packet animation
- Attack scenario selection
- Message interception controls
- Captured data panel
- Communication logs

### Demo Tab
- Side-by-side HTTP/HTTPS comparison
- Live login form demonstration
- Terminal output showing captured credentials
- Security best practices

### Terminal Tab
- Hacker-style interface
- Network scanning simulation
- ARP spoofing commands
- Packet sniffing demonstration
- Educational warnings

### Learn Tab
- MITM attack fundamentals
- Attack stage breakdown
- Different attack types explained
- Data theft examples

### Quiz Tab
- 5 interactive questions
- Immediate feedback
- Detailed explanations
- Score tracking

### Prevention Tab
- 6 key security measures
- Interactive security checklist
- Best practice guidelines
- Progress tracking

## 🤝 Contributing

This is an educational project. If you'd like to contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

## 📄 License

This project is created for **educational purposes only**. Feel free to use it for learning and teaching about cybersecurity.

## 👤 Author

**Ahmed Dinari**
- Email: ahmed.dinari@polytechnicien.tn
- GitHub: [@amedo007-poly](https://github.com/amedo007-poly)

## 🙏 Acknowledgments

- Created for cybersecurity education and awareness
- Inspired by the need for interactive security learning tools
- Built with modern web technologies for maximum accessibility

## 📞 Support

For questions, issues, or suggestions:
- Open an issue on GitHub
- Contact via email: ahmed.dinari@polytechnicien.tn

---

<div align="center">

**⚡ Understanding attacks helps us build better defenses ⚡**

Made with ❤️ for Cybersecurity Education

</div>
