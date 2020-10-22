import os
import tableprint as tp
import listener

from win10toast import ToastNotifier
toaster = ToastNotifier()

MY_EMAIL = 'tiagode@amazon.de'

meeting_status = { 'on': False, 'participants': [] }

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
                headers = ['Name', 'Email', 'PhoneTool']
                data = [[x.get('full_name'), x.get('email'), f'https://phonetool.amazon.com/users/{x.get("email").split("@")[0]}'] for x in present_participants]
                tp.table(data, headers)

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
    print('Websocket messages log: ', listener.get_messages_file_path())
    while True:
        try:
            listener.run(on_event)
        except Exception as e:
            print('Connection failed', e)
            toaster.show_toast('Error', 'Connection failed, please login again!')