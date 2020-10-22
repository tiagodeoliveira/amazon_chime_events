import os
import tableprint as tp
import listener
from configparser import ConfigParser

from win10toast import ToastNotifier
toaster = ToastNotifier()

meeting_status = { 'on': False, 'participants': [] }

config = ConfigParser()
config.read('config.ini')

MY_EMAIL = config.get('config', 'my_email')
USER_PROFILE_URL = config.get('config', 'user_profile_url')
COMPANY_DOMAIN = config.get('config', 'company_domain')

def cls():
    os.system('cls' if os.name=='nt' else 'clear')

def meeting_update(meeting_event):
    """
        Checks if MY_EMAIL is on a meeting or not
    """
    meeting = meeting_event['data']
    meeting_id = meeting['record']['id']
    participants = meeting['record']['participants']
    me = next(filter(lambda x: x['email'] == MY_EMAIL, participants))
    
    if me:
        if me['status'] == 'present':
            if meeting_status['on'] == False:
                toaster.show_toast('Meeting Started!', f'You are connected to {meeting_id}')

            meeting_status['on'] = True
            present_participants = list(filter(lambda x: x.get('status', '') == 'present', participants))
            
            present_emails = sorted(filter(None, [p.get('email', '') for p in present_participants if type(p) is dict and 'email' in p]))
            previous_present_emails = sorted(filter(None, [p.get('email', '') for p in meeting_status['participants']]))

            if present_emails != previous_present_emails:
                meeting_status['participants'] = present_participants

                cls()
                print('I am on a meeting! With:')
                headers = ['Name', 'Email', 'User Profile']
                data = [[x.get('full_name'), x.get('email'), f'{USER_PROFILE_URL}{x.get("email").split("@")[0]}' if f'@{COMPANY_DOMAIN}' in x.get('email') else 'n/a'] for x in present_participants if x.get('email') and x.get('full_name')] 
                tp.table(data, headers, width=[40, 65, 48])

        elif meeting_status['on'] == True:
            cls()
            meeting_status['on'] = False
            meeting_status['participants'] = []
            toaster.show_toast('Meeting finished!', f'You are disconnected from {meeting_id}')

def on_event(evt_type, evt_message):
    if evt_type == 'Roster':
        meeting_update(evt_message)

    if (evt_type.startswith('ws_')):
        toaster.show_toast(evt_type, evt_message)

if __name__ == '__main__':
    cls()
    while True:
        try:
            listener.run(on_event)
            toaster.show_toast('Stop', 'Listener is stopped')
            print('Listener is stopped')
        except Exception as e:
            print('Connection failed', e)
            toaster.show_toast('Error', 'Connection failed, please login again!')
            print('Connection error', e)
        finally:
            print('Execution has stopped')