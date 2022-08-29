import requests
import hashlib
import sys

# Requesting data i.e leaked passwords from API
def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching:{res.status_code}, check API and try again')
	return res

# Checking if password been leaked and returning the count
def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h,count in hashes:
		if h == hash_to_check:
			return count
	return 0


def pwned_api_check(password):
	#Converting password into SHA1 hash
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	# Applying K anonymity by sending only first five chars to API
	response = request_api_data(first5_char)
	# Returning how many times a password been leaked
	return get_password_leaks_count(response, tail)

def main(args):
	# Text file containing passwords to check
	file = open(f'{args}', 'r')
	password_to_check = file.read().splitlines()
	for password in password_to_check:
		# Checking if a passowrd has ever been leaked and getting the count
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times... you should probably change your password!')
		else:
			print(f'{password} was NOT found. Carry on!')
	return 'done!'

if __name__ == '__main__':
	sys.exit(main(sys.argv[1]))
