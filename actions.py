import os
import tableprint as tp
import listener
import tempfile
import time
from configparser import ConfigParser

#from win10toast import ToastNotifier
#toaster = ToastNotifier()

meeting_status = { 'on': False, 'participants': [] }

"""
    To properly works this script need the 3 properties below, they should be inside a config.ini file (on the same dir as this script)
    For example:

    [config]
    my_email = me@my-org.de
    user_profile_url = https://users.my-org.de/user/
    company_domain = my-org.de or my-org.
"""
config = ConfigParser()
config.read('config.ini')
MY_EMAIL = config.get('config', 'my_email')
USER_PROFILE_URL = config.get('config', 'user_profile_url')
COMPANY_DOMAIN = config.get('config', 'company_domain')

def notify(title, text):
    os.system("""
              osascript -e 'display notification "{}" with title "{}"'
              """.format(text, title))

def cls():
    os.system('cls' if os.name=='nt' else 'clear')

def meeting_update(meeting_event):
    """
        Checks if MY_EMAIL is on a meeting
        If so, print a table with the participants of that meeting
    """
    meeting = meeting_event['data']
    meeting_id = meeting['record']['id']
    participants = meeting['record']['participants']
    me = next(filter(lambda x: x['email'] == MY_EMAIL, participants))

    if me:
        if me['status'] == 'present':
            if meeting_status['on'] == False:
                notify('Meeting Started!', f'You are connected to {meeting_id}')

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
            notify('Meeting finished!', f'You are disconnected from {meeting_id}')
            print('Meeting has ended!')

def on_event(evt_type, evt_message):
    if evt_type == 'Roster':
        meeting_update(evt_message)

    if (evt_type.startswith('ws_')):
        notify(evt_type, evt_message)

if __name__ == '__main__':
    while True:
        try:
            messages_log_file = f'{tempfile.gettempdir()}/{time.strftime("%Y%m%d-%H%M%S")}.log'
            print('Running websocket! Log:', messages_log_file)
            listener.run(on_event, messages_log_file)
            notify('Stop', 'Listener is stopped')
            print('Listener is stopped')
        except Exception as e:
            print('Connection error', e)
        finally:
            print('Execution has stopped')
            notify('Error', 'Trying to reconnect!')
