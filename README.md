## My-Login: Minimalist TTY Display Manager
A lightweight, terminal-based display manager (login manager) written in C. It uses PAM (Pluggable Authentication Modules) for secure user verification and is specifically configured to launch the Niri Wayland compositor, though it can be adapted for any session.
## Features
- PAM Integration: Handles standard Linux authentication, account management, and session opening/closing.

- Secure Password Handling: Disables terminal echo during password entry.

- Environment Setup: Automatically sets up critical environment variables including HOME, USER, XDG_RUNTIME_DIR, and PATH.

- Wayland Ready: Pre-configured with XDG_SESSION_TYPE=wayland and seat management.

- Clean UI: A simple, centered TTY interface using ANSI escape codes.

- Process Isolation: Forks a child process for the user session and waits for it to terminate before returning to the login prompt.

## Prerequisites
To compile and run this manager, you need the PAM development libraries installed on your system.
### On Arch Linux:
```Bash
sudo pacman -S gcc pam
```
### On Ubuntu/Debian:
```Bash
sudo apt install gcc libpam0g-dev
```
## ⚠️ Safety Note
Since this program handles passwords and runs as root, ensure you have a way to return to a standard TTY (usually Ctrl+Alt+F2 through F6) if your session fails to launch or if you get stuck in the loop.

## How It Works
- UI Loop: The program draws a box in the center of the terminal and waits for username/password input.

- Authentication: It passes credentials to the PAM stack via pam_authenticate.

- Session Setup: * pam_open_session is called to register the login.
    
    - XDG_RUNTIME_DIR is verified and created if missing.

- Hand-off:

    - The process forks.

    - The child process drops root privileges using setuid and setgid to match the logged-in user.

    - The child execs a login shell (-l) to source user profiles (like .bash_profile) and finally launches the window manager.

-Cleanup: When the window manager exits, the parent process closes the PAM session and returns to the login screen.