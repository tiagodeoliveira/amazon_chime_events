import json
import time
import requests
import uuid
import queue
import webview
import websocket
import tempfile
import time

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

WAIT_TIME_IN_SEC = 60
WAIT_TIME_STEP_IN_SEC = 1
BASE_URL = 'https://api.express.ue1.app.chime.aws'
SIGNIN_URL = 'https://signin.id.ue1.app.chime.aws/'

messages_log = tempfile.TemporaryFile(suffix='.log', buffering=0, prefix=time.strftime("%Y%m%d-%H%M%S"))

def get_messages_file_path():
    return messages_log.name

def log_ws_message(message):
    messages_log.write(bytes(f'{message}\n', 'utf-8'))
    messages_log.flush()

def send_ws_message(ws, message):
    ws.send(message)
    log_ws_message(f'SEND - {message}')

######################################################################################
# Event handler
######################################################################################
def process_events(events_queue, ws, on_event):
    """
        Here is where the events are taken from the queue and further parsed.
    """
    count = 0
    while True:
        event_string = events_queue.get()
        event = json.loads(event_string)
        count += 1        
        klass = event.get('data', {}).get('klass', '')
        if klass == 'JoinableMeetings2':
            meeting = event.get('data', {}).get('record', {}).get('JoinableMeetings')
            if meeting:
                channel = meeting[0].get('Channel', '')
                send_ws_message(ws, f'3:::{{"type":"subscribe","channel":"{channel}"}}')

        on_event(klass, event)

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
    log_ws_message(f'RECV - {message}')
    if message.startswith('3:'):
        events_queue.put(message.split('::')[1])
        it = message.split(':')[1]
        send_ws_message(ws, f'6:::{it}')
    elif message == '2::':
        send_ws_message(ws, f'2::')

def on_error(ws, error, on_event):
    on_event('ws_error', error)
    ws.close()

def on_close(ws, on_event):
    on_event('ws_closed', 'Websocket closed!')
    ws.close()

def on_open(ws, profile_id, device_id, on_event):
    def run(*args):
        send_ws_message(ws, f'3:::{{"type":"subscribe","channel":"profile!{profile_id}"}}')
        send_ws_message(ws, f'3:::{{"type":"subscribe","channel":"webclient_device!{device_id}"}}')
        send_ws_message(ws, f'3:::{{"type":"subscribe","channel":"profile_presence!{profile_id}"}}')
        
    thread.start_new_thread(run, ())
    on_event('ws_open', 'Connection established!')

def handle_ws(socket_url, profile_id, device_id, on_event):
    events_queue = queue.Queue()
    ws = websocket.WebSocketApp(
        socket_url,
        on_message = lambda ws, message: on_message(ws, message, events_queue),
        on_error = lambda ws, error: on_error(ws, error, on_event),
        on_close = lambda ws: on_close(ws, on_event)
    )
    ws.on_open = lambda ws: on_open(ws, profile_id, device_id, on_event)
    thread.start_new_thread(process_events, (events_queue, ws, on_event))
    ws.run_forever()

######################################################################################
# Main
######################################################################################
def run(on_event):
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
        raise Exception('WebSocket Url not found')

    websocket_key, session_id = get_websocket_key(websocket_url, session_token)

    with open('config.ini', 'w') as f:
        config.write(f)

    profile_id = session_data['Session']['Profile']['id']
    device_id = session_data['Session']['Device']['DeviceId']

    net_address = urlparse(websocket_url).netloc
    url = f'wss://{net_address}/socket.io/1/websocket/{websocket_key}?session_uuid={session_id}'

    handle_ws(url, profile_id, device_id, on_event)
    messages_log.close()

if __name__ == '__main__':
    run(lambda event_type, event_content: print('On Event', event_type, event_content))