import hashlib
import json

def is_valid_credentials(username, password):
	hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

	with open('creds.json') as f:
		creds_json = json.load(f)
	
	auth_dict = {cred['username']: cred['password_hash'] for cred in creds_json['creds']}

	return username in auth_dict and hashed_password == auth_dict[username]

def main():
	username = input("Username: ")
	password = input("Password: ")

	is_valid = is_valid_credentials(username, password)

	if is_valid:
		print("here is a secret")
	else:
		print("no")

if __name__ == "__main__":
	main()