# Make sure Ccnet Server has been started.

# Create AsyncClient instance and connect with Ccnet Server.

# As receive message operation is handled by MqClientProc, we need to create MqClientProc instance and from the instance subscribe event source such as seaf_server.event subscribed in demo. In the demo, using EventsMQListener to encapsulate above operation and create a worker thread to mointer message queue, if there is a message the worker thread will log related information.

# AsyncClient instance start event loop.

import time
import sys
import signal
import threading
import Queue
import logging

import libevent

from ccnet.async import AsyncClient
from message_handlers import handle_message, log_event_to_file

class EventLoggingThread(threading.Thread):
    def __init__(self, event_queue):
        threading.Thread.__init__(self)
        self.recieved_events = event_queue

    def run(self):
        while True:
            log_event_to_file()

class EventHandlerThread(threading.Thread):
    def __init__(self, event_queue):
        threading.Thread.__init__(self)
        self.recieved_events = event_queue

    def run(self):
        while True:
            recieved_message = self.recieved_events.get()
            handle_message(recieved_message.app, recieved_message.body.split('\t'))

class EventListener(object):
    def __init__(self):
        self._event_queue = Queue.Queue()
        self._event_listener_thread = None
        self._event_queue_client = None
        self._event_logging_thread = None

    def event_callback(self, recieved_event):
        self._event_queue.put(recieved_event)
    
    def startListening(self, ccnetClient):
        if self._event_listener_thread is None:
            self._event_listener_thread = EventHandlerThread(self._event_queue)
            self._event_listener_thread.setDaemon(True)
            self._event_listener_thread.start()
        
        if self._event_logging_thread is None:
            self._event_logging_thread = EventLoggingThread(self._event_queue)
            self._event_logging_thread.setDaemon(True)
            self._event_logging_thread.start()
        
        self._event_queue_client = ccnetClient.create_master_processor('mq-client')
        self._event_queue_client.set_callback(self.event_callback)
        subscribed_operations = ('syncwerk_server_daemon.stats', 'syncwerk_server_daemon.event')
        self._event_queue_client.start(*subscribed_operations)
        

def createAsyncClient(eventBase, check_connection_only=False):
    
    client = AsyncClient('/etc/syncwerk', eventBase)

    try:
        client.connect_daemon()
        if check_connection_only == True:
            logging.info('File daemon is ready')
            return 0
        else:
            logging.info('Connected to ccnet server')
            return client
    except Exception:
        logging.info('Waiting for file daemon to be ready...')
        time.sleep(5)
        return createAsyncClient(eventBase)

def terminateEvent(*arg):
    sys.exit(0)

def startEventListening(check_connection_only=False):
    event_base = libevent.Base()
    if check_connection_only:
        result = createAsyncClient(event_base, check_connection_only)
        return result
    ccnet_client = createAsyncClient(event_base, check_connection_only)
    event_listener = EventListener()
    event_listener.startListening(ccnet_client)
    if signal is not None:
        terminate_signal = libevent.Signal(event_base, signal.SIGTERM, terminateEvent, None)
        terminate_signal.add()
        intterupt_signal = libevent.Signal(event_base, signal.SIGINT, terminateEvent, None)
        intterupt_signal.add()
    try:
        ccnet_client.main_loop()
    except Exception:
        logging.info('Exiting due to unexpected error')
        sys.exit()

def main():
    startEventListening()
    # while True:
    #     time.sleep(60)

if __name__ == "__main__":
    main()