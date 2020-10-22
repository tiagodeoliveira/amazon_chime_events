# amazon_chime_events

Simple project that connects to the Amazon Chime App internal websocket and extract the events which are happening on the specific account.

```
$ pip3 install -r requirements.txt

# This will run only the websocket connection and print out all the messages received
$ python3 listener.py 

# This will start the websocket connection and run custom actions on top of those messages 
# This specific file uses windows 10 toast notifications, you might have problems on other systems
$ python3 actions.py
```

