import sys
import json
import time
import requests
import uuid
import queue
import webview
import websocket
import pprint
import conference_status

try:
    import thread
except ImportError:
    import _thread as thread

from configparser import ConfigParser
from urllib.parse import urlparse

config = ConfigParser()
config.read('config.ini')
if 'main' not in config.sections():
    config.add_section('main')

pp = pprint.PrettyPrinter(indent=4)

WAIT_TIME_IN_SEC = 60
WAIT_TIME_STEP_IN_SEC = 1
BASE_URL = 'https://api.express.ue1.app.chime.aws'
SIGNIN_URL = 'https://signin.id.ue1.app.chime.aws/'

######################################################################################
# Event handler
######################################################################################
def process_events(events_queue, ws):
    """
        Here is where the events are taken from the queue and further parsed.
    """
    count = 0
    while True:
        event = json.loads(events_queue.get())
        count += 1        
        klass = event.get('data', {}).get('klass', '')
        if klass == 'JoinableMeetings2':
            meeting = event.get('data', {}).get('record', {}).get('JoinableMeetings')
            if meeting:
                channel = meeting[0].get('Channel', '')
                ws.send(f'3:::{{"type":"subscribe","channel":"{channel}"}}')
        elif klass == 'Roster':
            conference_status.meeting_update(event)

        # print(count, ' | ====================================================')
        # print('klass:', klass)
        # pp.pprint(event.get('data', {}))

        events_queue.task_done()

######################################################################################
# Chime login window
######################################################################################
def wait_chime_login_link(window, return_list):
    """
        Waits the chime login link to be generated
    """
    count = 0
    while True:
        chime_launch_link = window.get_elements('#chime-launch-link')

        if chime_launch_link and chime_launch_link[0]:
            return_list.append(chime_launch_link[0]['href'])
            window.destroy()
            break
        
        if count >= WAIT_TIME_IN_SEC:
            window.destroy()
            break

        time.sleep(WAIT_TIME_STEP_IN_SEC)

def prompt_credentials():
    return_list = []
    window = webview.create_window('Please login on Chime', SIGNIN_URL, frameless=False)
    webview.start(wait_chime_login_link, [ window, return_list ] )
    return return_list[0]

######################################################################################
# Chime device setup
######################################################################################
def get_token():
    chime_url = config.get('main', 'chime_url', fallback=None)
    if not chime_url:
        chime_url = prompt_credentials()
        config.set('main', 'chime_url', chime_url)

    chime_token = urlparse(chime_url).query
    return chime_token.split('=')[1]

def get_device_id():
    device_id = config.get('main', 'device_id', fallback=None)
    if not device_id:
        device_id = str(uuid.uuid4())
        config.set('main', 'device_id', device_id)
    
    return device_id

def get_device_token():
    device_token = config.get('main', 'device_token', fallback=None)
    if not device_token:
        device_token = str(uuid.uuid4())
        config.set('main', 'device_token', device_token)

    return device_token

def get_session_data(chime_token):
    session_request_payload = {
        'Token': chime_token,
        'Device':{
            'DeviceId': get_device_id(),
            'Platform': 'webclient',
            'DeviceToken': get_device_token(),
            'Capabilities': 1,
            'CapabilitiesV2': {
                'CCP': '2',
                'DeviceBuildVersion': '1.0.209967.0'
            }
        }
    }

    session_data_response = requests.post(f'{BASE_URL}/signin/sso_sessions', data = json.dumps(session_request_payload))
    session_data = session_data_response.json()

    session_token = session_data_response.headers.get('X-Set-Chime-Auth-Token')
    return session_data, session_token

def get_websocket_url(session_token):
    headers = {
        'x-chime-auth-token': f'_aws_wt_session={session_token}'
    }
    response = requests.request("GET", f'{BASE_URL}/psh/endpoint', headers=headers)
    if response.status_code == 200:
        return response.json()['WebSocketURL']
    else:
        print('Could not fetch websocket url', response.text)
        return None

def get_websocket_key(websocket_url, session_token):
    websocket_name = urlparse(websocket_url).netloc
    session_id = str(uuid.uuid4())
    headers = {
        'x-chime-auth-token': f'_aws_wt_session={session_token}'
    }

    request_url = f'{BASE_URL}/psh/{websocket_name}/socket.io/1/?session_uuid={session_id}'
    response = requests.request("GET", request_url, headers=headers)
    response_text = response.text
    return response_text.split(':')[0], session_id

def activate_device(session_token):
    headers = {
        'x-chime-auth-token': f'_aws_wt_session={session_token}'
    }
    requests.put(f'{BASE_URL}/copr/devicestatus', data = json.dumps({'Status': 'Active'}), headers=headers)

######################################################################################
# Websocket handling
######################################################################################
def on_message(ws, message, events_queue):
    if message.startswith('3:'):
        events_queue.put(message.split('::')[1])
        it = message.split(':')[1]
        ws.send(f'6:::{it}')
    elif message == '2::':
        ws.send('2::')

def on_error(ws, error):
    print('error', error)

def on_close(ws):
    sys.exit(-1)

def on_open(ws, profile_id, device_id):
    def run(*args):
        ws.send(f'3:::{{"type":"subscribe","channel":"profile!{profile_id}"}}')
        ws.send(f'3:::{{"type":"subscribe","channel":"webclient_device!{device_id}"}}')
        ws.send(f'3:::{{"type":"subscribe","channel":"profile_presence!{profile_id}"}}')
        
    thread.start_new_thread(run, ())
    print('Connection established!')

def handle_ws():

    events_queue = queue.Queue()
    ws = websocket.WebSocketApp(
        url,
        on_message = lambda ws, message: on_message(ws, message, events_queue),
        on_error = on_error,
        on_close = on_close
    )
    ws.on_open = lambda ws: on_open(ws, profile_id, device_id)
    thread.start_new_thread(process_events, (events_queue, ws))
    ws.run_forever()

######################################################################################
# Main
######################################################################################
if __name__ == '__main__':
    chime_token = get_token()
    session_data, session_token = get_session_data(chime_token)
    
    if not session_token:
        config.clear()
        config.add_section('main')
        chime_token = get_token()
        session_data, session_token = get_session_data(chime_token)

    activate_device(session_token)
    websocket_url = get_websocket_url(session_token)
    
    if not websocket_url:
        sys.exit(-1)

    websocket_key, session_id = get_websocket_key(websocket_url, session_token)

    with open('config.ini', 'w') as f:
        config.write(f)

    profile_id = session_data['Session']['Profile']['id']
    device_id = session_data['Session']['Device']['DeviceId']

    net_address = websocket_name = urlparse(websocket_url).netloc
    url = f'wss://{net_address}/socket.io/1/websocket/{websocket_key}?session_uuid={session_id}'

    handle_ws()
