import sys

MY_EMAIL = 'tiagode@amazon.de'

on_meeting = False
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
            on_meeting = True
        else:
            on_meeting = False

        sys.stdout.write("\033[F") 
        sys.stdout.write("\033[K")
        print('On Meeting: ', on_meeting)
