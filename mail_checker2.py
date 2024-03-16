#!/home/$USER/Documents/Projects/email_check/venv/bin/python

# This script is meant to check email state and save the
# output into a file with css formatting. This file can be
# read by genmon to show on the xfce4 panel.
# Almost all things, related to mails are done with IMAPClient,
# except fetching mails for gmail. The native gmail python
# library generates three times less requests, so it's preferred.

import subprocess
import logging
from user_settings import (
    GOOGLE_LOGIN, COLORS, EMAIL_IS_FRESH, 
    EMAILS_NOTIFY, EXPECTED_MESSAGES, 
    ANYMAIL_LOGIN, TZ, GOOGLE_IMAP,
    IDLERS, POLLING_TIME
)
from os import path, system
from imapclient import IMAPClient
from imaplib import IMAP4
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from httplib2 import ServerNotFoundError
from dataclasses import dataclass, field
from google.auth.exceptions import TransportError
from threading import Thread, Event
from queue import Queue
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header
from email.utils import parsedate_to_datetime
from socket import gaierror
from time import sleep
from httplib2.error import ServerNotFoundError
from typing import Literal

DEBUG = False

# simple info about a mail
@dataclass
class Onemail:
    From: str = ''
    Subject: str = ''
    Date: datetime|None = None

# a dataclass for result to return from any read mail function
# Now with only two fields it makes little sense to use a
# datacalss here, but it's convenient in a case new fields
# are required
@dataclass
class Result:
    mailbox: str
    msg_headers: list[Onemail] = field(default_factory=list)

class WorkWithMailBase:
    """The class contains most usefull functions to communicate
    with a mailbox, but no login or logout logic. This should
    be implemented from the outside.
    Sidenote - it makes no sense to take imap_client as init
    argument, because then we would have to maintain the session,
    otherwise it will become invalid.
    """
    def __init__(self, imap_address: str, mailboxes: list[str], ident: str, tz: timezone) -> None:
        """
        Args:
            imap_address (str): imap server address
            mailboxes (list[str]): a list of mailboxes to check
            ident (str): account nickname. Login name could be used instead,
                        but if we have to send it to the class anyway, why
                        don't just send a more convenient identifier
            tz (timezone): timezone
        """
        self.imap_address = imap_address
        self.mailboxes = mailboxes
        self.ident = ident
        self.tz = tz

    def show_all_folders(self, imap_client: IMAPClient) -> None:
        """Prints all folders on the account
        """
        # No error catching because this function is meant just
        # for the initial setup, there is literally no point to call it later
        with imap_client as client:
            logger.debug('Folders requested')
            print(client.list_folders())

    def get_messages(
            self,
            imap_client: IMAPClient,
            search_val: list=['UNSEEN'],
    ) -> list[Result] | None:
        """Requests all messages, which are fitting to the search_val.
        Requests only messages UIDs and headers, not bodies.

        Args:
            imap_client (IMAPClient): a logged in instance if IMAPClient
            search_val (list, optional): a list of search criterias.
                        Defaults to ['UNSEEN'].

        Returns:
            list[Result] | None: returns either list of Result instances,
                        where Result contains a mailbox name and parsed
                        headers of found messages or None if an error
                        occured
        """
        result = [] # list of Result()
        # taking already logged in client
        with imap_client as client:
            logger.debug(f'Email {self.ident}: Requesting message IDs and headers')
            try:
                for mailbox in self.mailboxes:
                    mailbox_result = Result(mailbox=mailbox)
                    client.select_folder(mailbox, readonly=True)
                    uids = client.search(search_val)
                    if uids:
                        # Fetch email headers for the matching emails
                        messages = client.fetch(uids, ['BODY.PEEK[HEADER.FIELDS (FROM DATE SUBJECT)]'])
                        # go over row emails
                        for msg in messages.values():
                            # initialize the Onemail instance to accumulate fields
                            tmp_result_item = Onemail()
                            # convert
                            msg = message_from_bytes(list(msg.values())[1])
                            # get header fields we requested earlier
                            for header_part in ['From', 'Date', 'Subject']:
                                header_part_data = msg.get(header_part)
                                if header_part_data is None:
                                    continue
                                # decode header item. Can get several tuples as a result
                                decoded = decode_header(header_part_data)
                                # to gather text from all tuples
                                accum_text = ''
                                for decoded_item in decoded:
                                    text, encoding = decoded_item
                                    # if bytes then encode using reseived encoding or a default
                                    # one, if encoding is None
                                    if isinstance(text, bytes):
                                        if encoding is None:
                                            accum_text += text.decode()                       
                                        else:
                                            try:
                                                accum_text += text.decode(encoding)
                                            # some rare emails have an unknown encoding
                                            except LookupError:
                                                accum_text += text.decode()
                                    # if the data isn't encoded, it's very likely a date
                                    else:
                                        try:
                                            accum_text = parsedate_to_datetime(text)
                                        # but if it's not a date then just save it like it is
                                        except ValueError:
                                            accum_text += text
                                # save in Onemail
                                setattr(tmp_result_item, header_part, accum_text)
                            # check the datetime object so we can process it later without errors
                            if isinstance(tmp_result_item.Date, datetime):
                                # some emails have no timezone. We assume it's utc then
                                if tmp_result_item.Date.tzinfo is None:
                                    tmp_result_item.Date = tmp_result_item.Date.replace(tzinfo=timezone.utc)
                            # if no, just assign something to prevent errors
                            else:
                                tmp_result_item.Date = datetime.now(tz=self.tz)
                            # add the header to the total result
                            mailbox_result.msg_headers.append(tmp_result_item)
                        logger.debug(f'Email {self.ident}: Got messages data for mailbox {mailbox}')
                    # add up the intermediate result, regardless of it containing
                    # emails headers or being empty
                    result.append(mailbox_result)
                return result
            except IMAP4.error:
                logger.error(f'Email {self.ident}: Probably IMAPClient issue, for example, not logged in')
            except (IMAP4.abort, gaierror):
                logger.error(f'Email {self.ident}: Received an error, probably network issue')

    def go_idle(
            self,
            imap_client: IMAPClient,
            stop_evnt: Event,
            queue: Queue,
            imap_conn_time: int=25,
            mailbox: str='INBOX',
    ) -> None:
        """
        Connects to the server, establishes idle. Server drop connections
        in 10 - 30 minutes, so every 25 minutes by default we'll be
        reestablishing it. Every 60 seconds the stop_event and new
        messages are checked. Stop event is necessary, because in a case
        of network loss, the connection won't signal anyhow, neither
        it will reestablish by itself. Also it has to be reset in a case
        of token expiration for oauth2.

        Args:
            imap_client (IMAPClient): a logged in client
            stop_evnt (Event): an event to gracefully stop execution
            queue (Queue): a queue where the thread will be placing the
                            data, recieved from the server
            imap_conn_time (int, optional): Servers drop connection after
                            a while silently, this time the connection is
                            assumed to not be dropped. Defaults to 25.
            mailbox (str, optional): idle can listen to only one mailbox
                            at a time. If necessary more than one - get
                            more threads. Defaults to 'INBOX'.
        """
        logger.info(f'Email {self.ident}, mailbox {mailbox}: Starting idle with conn time {imap_conn_time}')
        try:
            with imap_client as client:
                # the template for processed push messages
                queue_reply = {
                    'message_provider': 'idle',
                    'ident': self.ident,
                    'mailbox': mailbox,
                    'message': []
                }
                counter = imap_conn_time
                client.select_folder(mailbox, readonly=True)
                client.idle()
                while not stop_evnt.is_set():
                    # reset idle if it's time
                    if counter == 0:
                        # if the connection is already dropped by the server, an attempt to
                        # cancel it will cause 'imaplib.IMAP4.abort: socket error: EOF'
                        logger.debug(f'Email {self.ident}, mailbox {mailbox}: Stopping idle by counter')
                        client.idle_done()
                        counter = imap_conn_time
                        logger.debug(f'Email {self.ident}, mailbox {mailbox}: Starting idle by counter')
                        client.idle()
                    # leave the waiting state every minute to check the stop event. If a message
                    # arrives, waiting state will return earlier
                    responses = client.idle_check(timeout=60)
                    # if there are notifications, we returned not via timeout
                    if responses:
                        queue_reply['message'].clear() # clear events
                        logger.info(f'Email {self.ident}, mailbox {mailbox}: Got message {responses}')
                        # reset the timer, because a pushed message renews the connection
                        counter = imap_conn_time
                        # there can be several messages
                        for item in responses:
                            match item:
                                case (_, b'EXISTS' | b'EXPUNGE' as msg):
                                    queue_reply['message'].append(msg.decode())
                                # looks like this in gmail reply
                                # [(1323, b'FETCH', (b'UID', 3154, b'FLAGS', (b'\\Seen',)))]
                                # and this is mailru for example
                                # [(1969, b'FETCH', (b'FLAGS', (b'\\Seen',)))]
                                case (_, b'FETCH', (*_, b'FLAGS', flags)):
                                    # the most common case
                                    if b'\\Seen' in flags:
                                        queue_reply['message'].append('seen')
                                    else:
                                        # more rare case - mark as unseen. No point to keep seen
                                        # messages, so we have to request it as well
                                        queue_reply['message'].append('unseen')
                                # idle_conn_time is too long, though not all servers send it
                                # gmail doesn't, it's completely silent
                                case (b'BYE', *_):
                                    stop_evnt.set()
                                case _:
                                    logger.debug('Unknown event type detected.')
                                    queue_reply['message'].append('unknown')
                        queue.put(queue_reply)
                    # if timeout is exceeded and nothing came from the server
                    # we dec the counter, so after imap_conn_time we can reestablish
                    # the connection
                    else:
                        counter -= 1
                # stop by the event
                else:
                    logger.info(f'Email {self.ident}, mailbox {mailbox}: Stopping idle by stop event')
                    client.idle_done()
        except IMAP4.abort:
            logger.error(f'Email {self.ident}, mailbox {mailbox}: Received an IMAP4.abort exception')
            stop_evnt.set()
            sendmessage(f'Idler {self.ident} is out because of IMAP4.abort')
        except Exception as e:
            stop_evnt.set()
            logger.error(f'Email {self.ident}, mailbox {mailbox}: Received exception: {e}', exc_info=True)
            sendmessage(f'Idler {self.ident} is out because of IMAP4.abort, {str(e)}')

    def check_service_reacheable(self) -> bool:
        """Pings the imap server, to check if it's
        reacheable.

        Returns:
            bool: The service (and the network) is reacheable
                        'True', or not 'False'
        """
        response = system(f'ping -c 1 {self.imap_address}')
        if response == 0:
            logger.debug(f"{self.imap_address} is up!")
            return True
        else:
            logger.debug(f"{self.imap_address} is down!")
            return False

    def wait_network(self) -> None:
        """Waits for the service to be reacheable, constantly
        increasing the wait interval between attempts, untill
        it's a few minutes. Method is done when the service
        is ready
        """
        logger.debug(f'Start waiting {self.imap_address}')
        wait_time = 10
        while not self.check_service_reacheable():
            if wait_time < 159:
                wait_time = wait_time * 2
            sleep(wait_time)
        logger.info(f'End waiting for {self.imap_address} with wait_time = {wait_time}')


class WorkWithGmail(WorkWithMailBase):

    def __init__(
        self,
        imap_address: str,
        client_secrets_file: str,
        token_file: str,
        scopes: list[str],
        login: str,
        mailboxes: list[str],
        ident: str,
        tz: timezone,
        imap_conn_time: int = 15,
    ) -> None:
        super().__init__(imap_address=imap_address, mailboxes=mailboxes, ident=ident, tz=tz)
        # check files in the script file dir
        # client_secrets_file should exist for oauth2
        root_dir = path.dirname(path.realpath(__file__))
        if path.exists(client_secrets_file_abs := path.join(root_dir, client_secrets_file)):
            self.client_secrets_file = client_secrets_file_abs
        else:
            raise FileNotFoundError(f'client_secrets_file {client_secrets_file} doesnt exist')
        # token_file can be absent. It will be created during program run
        self.token_file = path.join(root_dir, token_file)
        self.scopes = scopes
        self.login = login
        self.imap_conn_time = imap_conn_time
        self.service = None
        self.creds = None
        self.mapped_labels = {}
        self.stop_event = None

    def make_creds(self) -> None:
        """Takes care of OAuth2 authentification. Checks the token
        existence and it's validity, because the auth token expires
        in one hour. If necessary, user is asked to allow access
        to his account.

        Raises:
            TransportError: caused by network issues, for example
                        the network reacheability absense
        """
        # The file token.json stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if path.exists(self.token_file):
            self.creds = Credentials.from_authorized_user_file(self.token_file)
        # If there are no (valid) credentials available, let the user log in.
        # Hopefully it's a one time action
        if self.creds is None or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                try:
                    self.creds.refresh(Request())
                # if any error occured during requesting new access token
                # according to docs it will be this type.
                except TransportError:
                    logger.error('No network', exc_info=True)
                    self.creds = None
                # all other are critical too
                except Exception:
                    logger.error('An error occured during a Refresh() request', exc_info=True)
                    self.creds = None
            else:
                flow = InstalledAppFlow.from_client_secrets_file(self.client_secrets_file, self.scopes)
                try:
                    self.creds = flow.run_local_server(port=0, timeout_seconds=60)
                # if connection wasn't established, then when timeout is reached, we'll get
                # authorization_response = wsgi_app.last_request_uri.replace("http", "https")
                # AttributeError: 'NoneType' object has no attribute 'replace'
                except AttributeError:
                    logger.error('No network', exc_info=True)
                    # it's not a mistake. AttributeError doesn't explain what happened
                    # for a caller, but it's the network absense
                    raise TransportError
                except Exception:
                    logger.error('An error occured during the user access request', exc_info=True)
                    self.creds = None
            # Save the credentials for the next run
            with open(self.token_file, 'w') as token:
                logger.debug(f'Saving new access token {self.token_file}')
                token.write(self.creds.to_json())
    
    def refresh_token(self) -> None:
        """Oauth2 token can expire during idle connection.
        This function checks it's validity and, if token expired,
        requests a new one and restarts the idle via setting
        the stop_event
        """
        # requires self.creds to be sure, we already had asuccessful
        # login and self.stop_event to be sure idle is used. Otherwise
        # it makes no sense to continue
        if self.creds is None or self.stop_event is None:
            return
        if (creds := Credentials.from_authorized_user_file(self.token_file)).expired:
            logger.debug(f'{self.ident} requires token update. Setting the stop event')
            creds.refresh(Request())
            self.stop_event.set()

    def _map_label_ids_to_names(self) -> None:
        """User created labels have just IDs in message request
        answers, not the names, given by this user. Thus such IDs
        should be mapped to their names. Done once per script launch.
        """
        all_labels = self.show_all_labels()
        # find our mailboxes among label names
        for mailbox in self.mailboxes:
            for label in all_labels:
                if mailbox == label['name']:
                    self.mapped_labels[mailbox] = label['id']
                    break

    def go_idle(self, queue: Queue, stop_evnt: Event, mailbox: str='[Gmail]/All Mail') -> None:
        self.make_creds()
        # log in the client
        client = IMAPClient(self.imap_address)
        client.oauth2_login(self.login, self.creds.token)
        self.stop_event = stop_evnt
        super().go_idle(
            imap_client=client,
            stop_evnt=stop_evnt,
            # ident=self.ident,
            queue=queue,
            imap_conn_time=self.imap_conn_time,
            mailbox=mailbox
        )
        # remove stop_even if idle was done, thus we prevent
        # self.refresh_token from running
        self.stop_event = None

    def get_messages(self, search_val: list=['UNSEEN']) -> list[Result]|None:
        """The function is inherited from the base class. Works,
        but inefficient in comparison with native gmail
        python client, which causes three times less requests.
        """
        self.make_creds() # always check if still valid
        if self.creds is None:
            return
        client = IMAPClient(self.imap_address)
        client.oauth2_login(self.login, self.creds.token)
        return super().get_messages(
            imap_client=client,
            search_val=search_val
        )

    def get_messages_gmail_way(self, q_custom: str='') -> list[Result]|None:
        """Requests list of email IDs from gmail, then fetches the
        metadata for each email and returns it's parsed headers in
        Result()s

        Args:
            q_custom (str, optional): allows to change the search criteria.
                            Defaults to '', so the hardcoded criteria will
                            be used.

        Returns:
            list[Result] | None: returns either list of Result instances,
                        where Result contains a mailbox name and parsed
                        headers of found messages or None if an error
                        occured
        """
        def msgCallback(request_id: str, response: dict|None, exception: HttpError|None) -> None:
            """A callback function to gather results from batch request
            Args:
                request_id (str): request id, like 1, 2, ...
                response (dict|None): deserialized response object
                exception (HttpError|None): apiclient.errors.HttpError exception object if an HTTP
                            error occurred while processing the request, or None if no error
                            occurred
            """
            if exception is not None:
                logger.error(f'gmail: {exception}')
                nonlocal err
                err = True
            else:
                msg_list.append(response)

        logger.debug('Requesting message IDs')
        result = [ Result(mailbox) for mailbox in self.mailboxes ]
        err = False
        msg_list = [] # for raw emails
        try:
            self.make_creds() # always check if still valid
            if self.creds is None:
                return
            # Call the Gmail API
            service = build('gmail', 'v1', credentials=self.creds)
            # prepare a part of query for mailboxes to request mails from
            # if there wasn't any custom qerry
            if not q_custom:
                q_custom = ' OR '.join([ 'label:' + mailbox for mailbox in self.mailboxes ]) + ' AND is:unread'
            # get message ids
            tmp_result = service.users().messages().list(userId='me',q=q_custom).execute()
            # prepare the batch request for messages metadata
            logger.info(f'Got IDs for {(msg_amount := len(tmp_result.get("messages", [])))} messages')
            # if no messages       
            if not msg_amount:
                return result
            else:
                logger.debug('Requesting messages data')
                # Use the batchGet method to retrieve headers for multiple messages
                batch = service.new_batch_http_request()
                # prepare batch request to get each message metadata by it's ids
                # if no format specified, full messages will be retrieved
                for message_id in tmp_result.get('messages', []):
                    batch.add(service.users().messages().get(
                        userId='me', id=message_id['id'], format='metadata', metadataHeaders=['subject','date','from', 'X-GM-MSGID']
                        ), callback=msgCallback)
                batch.execute() # fetch
            for item in msg_list:
                headers = item.get('payload', {}).get('headers', [])
                ready_header = Onemail()
                for header in headers:
                    header_name = header.get('name')
                    value = header.get('value', '')
                    if header_name == 'Date':
                        # parse date
                        if value:
                            ready_header.Date = parsedate_to_datetime(value)
                            # some emails have no timezone. We assume it's utc then
                            if ready_header.Date.tzinfo is None:
                                ready_header.Date = ready_header.Date.replace(tzinfo=timezone.utc)
                        # shouldn't happen because I can't imagine an email
                        # without a date, but just in case
                        else:
                            ready_header.Date = datetime.now(tz=self.tz)
                        continue
                    setattr(ready_header, header_name, value)
                # message labels look like ['UNREAD', 'IMPORTANT', 'CATEGORY_PERSONAL', 'INBOX']
                # so we have to add this headers into proper class instance by it's mailbox
                if not self.mapped_labels:
                    self._map_label_ids_to_names()
                for res in result:
                    if self.mapped_labels[res.mailbox] in item['labelIds']:
                        res.msg_headers.append(ready_header)
                        break
            logger.debug('Got messages data')            
        except (HttpError, ServerNotFoundError, TransportError):
            logger.error(f'A network error happened', exc_info=True)
            return
        # even if we got some messages, the picture won't be full
        # if an error occured, so return None to make it clear
        # something went wrong
        if err:
            return None
        return result
    
    def show_all_labels(self) -> list[dict[str, str]]|None:
        """Lists all labels (folders in other mail providers) existing
        on the account
        """
        self.make_creds() # always check if still valid
        logger.debug('Labels requested')
        try:
            # Call the Gmail API
            service = build('gmail', 'v1', credentials=self.creds)
            # get the list of inbox directories
            labels= service.users().labels().list(userId='me').execute().get('labels', None)
            if labels is not None:
                return labels
        except (HttpError, ServerNotFoundError):
            logger.error(f'An error occurred', exc_info=True)
            raise TransportError


class WorkWithAnyMail(WorkWithMailBase):
    def __init__(
            self, 
            imap_address: str,
            login: str,
            passwd: str,
            mailboxes: list,
            ident: str,
            tz: timezone,
            idle_conn_time: int = 25,
    ) -> None:
        super().__init__(imap_address=imap_address, mailboxes=mailboxes, ident=ident, tz=tz)
        self.login = login
        self.passwd = passwd
        self.idle_conn_time = idle_conn_time

    def _get_loggedin_client(self) -> IMAPClient:
        """Loggs in via app password

        Returns:
            IMAPClient: a logged in instance
        """
        client = IMAPClient(self.imap_address)
        client.login(self.login, self.passwd)
        return client

    def show_all_folders(self) -> None:
        super().show_all_folders(self._get_loggedin_client())

    def get_messages(self, search_val: list=['UNSEEN']) -> list[Result]|None:
        return super().get_messages(
            imap_client=self._get_loggedin_client(),
            search_val=search_val
        )
    
    def go_idle(self, queue: Queue, stop_evnt: Event, mailbox: str = 'INBOX') -> None:
        super().go_idle(
            imap_client=self._get_loggedin_client(),
            stop_evnt=stop_evnt,
            queue=queue,
            imap_conn_time=self.idle_conn_time,
            mailbox=mailbox)


class ScreenOutput:
    def __init__(
            self,
            work_with_xmail_inst: list[WorkWithGmail|WorkWithAnyMail],
            colors: dict[str, str],
            email_is_fresh: timedelta,
            emails_notify: str,
            tz: timezone
    ) -> None:
        # a file to write result
        self.emails_notify = emails_notify
        # a timespan when a message counts as fresh
        self.email_is_fresh = email_is_fresh
        self.tz = tz # timezone
        self.colors = colors # colors for the output
        # WorkWith[G/ANY]mail instances
        self.xmails = work_with_xmail_inst
        # a dictionary of expected mails
        self.expected_messages = {}
        # is a case a script will work after midnight, expected
        # messages should be reset, so we should remember the day
        self.day = datetime.now(tz=tz).day
        # messages to keep checking for. Those which threshold
        # is already reached are expunged
        self.pending_for_alarm = {}
        # a list of idents where expected messages didn't arrive
        self.alarm = []
        # a dict to store fresh messages within EMAIL_IS_FRESH time
        # pattern <ident>: <time>
        self.fresh_messages = {}        
        logger.debug('Setting defaults for the output')
        # this is for tracking the mailboxes state, so any part
        # can be changed independently and the output string will
        # be assembled from this. Pattern:
        # ident1 = {
        #   'color': 'some_color',
        #   'items': {
        #       'mailbox1': int,
        #       'mailbox2': int
        #   }
        # }
        # initially items have strings with '-'
        self.notify_file_str = {}
        for mail in work_with_xmail_inst:
            self.output_no_data(mail.ident)

    def output_no_data(self, ident: str, color: Literal['default', 'error']='default') -> None:
        """Sets ident's mailboxes into a undentified state,
        namely '-'. Used for initial state and for a case
        of network issues

        Args:
            ident (str): email identifier
            color (Literal['default', 'error']): 'default' for the first
                            launch and 'error' if an error happened
                            during messages requests
        """
        self.notify_file_str[ident] = {
            'color': self.colors[color],
            'items': '-'
        }
        self._make_file()

    def _make_file(self) -> None:
        """Creates a css styled file. Assembles the string
        from data, contained in self.notify_file_str
        """
        logger.debug('Changing file')
        output = []
        for ident in self.notify_file_str:
            # for the first launch there will be '-' instead of numbers
            if isinstance(self.notify_file_str[ident]['items'], str):
                mail_string = self.notify_file_str[ident]['items']
            else:
                # the list for string parts
                mail_string = []
                for mailbox, mail_amount in self.notify_file_str[ident]['items'].items():
                    # take only those mailboxes, which have unseen letters
                    if mail_amount != 0:
                        mail_string.append(f'{mailbox} {mail_amount}')
                # assemble string if there are any unseen messages, otherwise 0
                mail_string = ", ".join(mail_string) if mail_string else 0
            # if ident in alarm list, we use different color
            if ident in self.alarm:
                color = self.colors['alarm']
            else:
                color = self.notify_file_str[ident]["color"]
            # add to css stuled formatted string
            output.append(
                f'<span foreground="{color}">'
                f'{ident}: {mail_string}</span>'
            )
        # writing down the file with proper styling
        with open(self.emails_notify, 'w') as f:
            f.write(
                f'<txt> {" | ".join(output)} </txt>'
            )

    def set_expected_msg(self, expected_messages: dict) -> None:
        """Turns human defined time into datetime objects.
        Changes the input data. Yes, it's a side effect.
        Requests messages for the dayspan before the script
        launch, so if any expected messages came, it should be
        taken into account.
        Then, based on this data, fills self.alarm, which
        contains email idents of missed expected messages and
        self.pending_for_alarm, which contains not missed but
        not arrived yet messages data.

        Args:
            expected_messages (dict): raw json-like definition
        """
        if not expected_messages:
            return
        logger.debug('Formatting expected_mssages to datetime objects')
        now = datetime.now(tz=self.tz) # current time
        # for those, which threshold expired
        expired = {}
        # for idents and email addresses of messages we want to request
        emails_for_request = {}
        for ident, messages in expected_messages.items():
            for msg in messages:
                user_time = datetime.strptime(msg['get_until'], "%H:%M").time() # convert string
                # combine today date with converted user time
                msg['get_until'] = datetime.combine(now.date(), user_time).replace(tzinfo=TZ)
                # if the threshold isn't reached
                if msg['get_until'] > now:
                    self.pending_for_alarm.setdefault(ident, []).append(msg)
                # otherwise, keep the record of it in expired and
                # add it to emails_for_request, so it will be requested
                # from the server
                else:
                    expired.setdefault(ident, []).append(msg)
                    emails_for_request.setdefault(ident, set()).add(msg['from'])
        self.expected_messages = expected_messages
        # nothing is missed
        if not expired:
            return
        # look among WorkWith[G/ANY]mail instances to find necessary
        for item in self.xmails:
            for ident, emails in emails_for_request.items():
                if item.ident == ident:
                    # special approach for gmail
                    if isinstance(item, WorkWithGmail):
                        # from:(somemail@some.com OR somemail2@some.su) after:2024/01/11
                        result = item.get_messages_gmail_way(
                            f'from:({" OR ".join(emails)}) after:{now.strftime("%Y/%m/%d")}'
                        )
                    # for the rest
                    else:
                        search_val = []
                        for email in emails:
                            search_val += ['FROM', email]
                        if len(search_val) > 2:
                            search_val.insert(0, 'OR')
                        # ['OR', 'FROM', 'somemail@some.com', 'FROM', 'somemail2@some.su', 'SINCE', '11-Jan-2024']
                        search_val += ['SINCE', now.strftime('%d-%b-%Y')]
                        result = item.get_messages(search_val)
                    # since the mailbox doesn't matter, we can extract only headers
                    # from the list of Result instances
                    result_headers = []
                    for res in result:
                        result_headers.extend(res.msg_headers)
                    # search missed messages among those, which we got from the server
                    for val in expired[ident]:
                        for header in result_headers:
                            # header.From can contain the sender name along with the
                            # email address, thus he have to check of the address in there
                            if val['from'] in header.From and val['subject'] == header.Subject:
                                # if found, then remove this header, so if we expect for two
                                # messages from the one source with the same subject,
                                # we'll see if it arrived
                                result_headers.remove(header)
                                break
                        else:
                            self.alarm.append(ident)
                            break
        logger.debug(f'All alarmed insts: {self.alarm}')
        logger.debug(f'All pending mails: {self.pending_for_alarm}')
    
    def ident_mails_to_zero(self, ident: str) -> None:
        """Goes over all mailboxes of some account (ident),
        and sets all mail numbers to 0.

        Args:
            ident (str): email ident
        """
        logger.debug(f'Dropped all mailboxes of {ident} to zero')
        for item in self.notify_file_str[ident]['items']:
            self.notify_file_str[ident]['items'][item] = 0
            # set the appropriate color for 0
            self.notify_file_str[ident]['color'] = self.colors['default']
            # remove from the accounting of fresh messages if any is there
            if ident in self.fresh_messages:
                del self.fresh_messages[ident]
        # show changes
        self._make_file()

    def check_Result(self, result: list[Result]|None, ident: str) -> None|dict[str, int]:
        """This method is called to analyze the Result instances.

        Args:
            result (list[Result]|None): the result instances. They contain
                        data with results of messages requests
            ident (str): the mail nickname
        """
        # if an error happened
        if result is None:
            self.output_no_data(ident, 'error')
            logger.debug('Result is None - error instead of a received messages')
            return
        # if it's just a first launch or after a network error,
        # the empty dicts should be created instead of strings
        if isinstance(self.notify_file_str[ident]['items'], str):
            self.notify_file_str[ident]['items'] = {}
        # a structure to return. So the outer thread can track
        # the mailbox state
        mailboxes_state = {
            'ident': ident,
            'msg_amount': 0
        }
        # we have to store the freshest message in
        # fresh_messages for periodic checks
        freshest_msg_date = None
        # remove fresh, because we reset the state anyway
        self.fresh_messages.pop(ident, None)
        self.notify_file_str[ident]['color'] = self.colors['default']
        for res in result:
            if res.msg_headers:
                # store messages amount
                mailboxes_state['msg_amount'] += (mails_amount := len(res.msg_headers))
                self.notify_file_str[ident]['items'][res.mailbox] = mails_amount
                now = datetime.now(tz=self.tz)
                for msg in res.msg_headers:
                    # if a message not only unseen but also freah
                    if (now - msg.Date) < self.email_is_fresh:
                        # find freshest datetime
                        if freshest_msg_date is None or freshest_msg_date < msg.Date:
                            freshest_msg_date = msg.Date
                    # check if an expected message arrived
                    if self.pending_for_alarm.get(ident) is not None:
                        for pending in self.pending_for_alarm[ident]:
                            if pending['from'] in msg.From and pending['subject'] == msg.Subject:
                                self.pending_for_alarm[ident].remove(pending)
                                break
            else:
                # no messages
                self.notify_file_str[ident]['items'][res.mailbox] = 0
        # if there are unseen messages at all
        if mailboxes_state['msg_amount']:
            # if there is a fresh message, save it's datetime
            if freshest_msg_date is not None:
                logger.debug(f'New fresh for {ident} set')
                self.fresh_messages[ident] = freshest_msg_date
                self.notify_file_str[ident]['color'] = self.colors['new_unseen']
            # if there are no fresh messages but unseen exist
            # set the appropriate color
            else:
                self.notify_file_str[ident]['color'] = self.colors['old_unseen']
        self._make_file()
        # return the messages amount for this ident
        return mailboxes_state

    def check_fresh_expired(self) -> None:
        """Compares the time in fresh_messages with the current
        time and if it's older than EMAIL_IS_FRESH value, then
        removes such from the accounting and changes the output
        color back to old_unseen
        """
        # if fresh messages exist at all, we should check if they
        # are still fresh
        if self.fresh_messages:
            now = datetime.now(tz=self.tz)
            # check if a such message was received longer than email_is_fresh ago
            remove = [] # for keys to remove if message is no longer fresh
            for ident, time in self.fresh_messages.items():
                if (now - time) > self.email_is_fresh:
                    # put color to normal
                    self.notify_file_str[ident]['color'] = self.colors['old_unseen']
                    remove.append(ident) # store key
                    logger.debug(f'Fresh {ident} expired')
                    self._make_file()
            # remove outdated keys from fresh_messages
            for ident in remove:
                del self.fresh_messages[ident]

    def check_expected_expired(self) -> None:
        """Goes through self.pending_for_alarm and checks if
        the arrival threshold is reached. Adds the ident into
        self.alarm if so
        """
        # if there are any messages to wait for
        if self.pending_for_alarm:
            now = datetime.now(tz=self.tz)
            # if the midnight came, we should change the date part
            # of expected messages and reenable all of them to pending
            if now.day != self.day:
                logger.debug('Day changed, resetting expected messages')
                self.day = now.day # store the new day
                for exp in self.expected_messages.values():
                    for msg in exp:
                        # add a day to each
                        msg['get_until'] = msg['get_until'] + timedelta(days=1)
                # reset all expected to pending
                self.pending_for_alarm = self.expected_messages.copy()
            # check if any of pending expired. The threshold is reached
            # but a message didn't come
            now = datetime.now(tz=self.tz)
            for ident, pending in self.pending_for_alarm.items():
                for email in pending:
                    if now > email['get_until']:
                        self.alarm.append(ident)
                        del self.pending_for_alarm[ident]
                        # also remove fresh if exists, color won't change anyway
                        self.fresh_messages.pop(ident, None)
                        self._make_file()
                        return

class Dispatcher:
    def __init__(
            self,
            work_with_xmail_inst: list[WorkWithGmail|WorkWithAnyMail],
            expected_messages: dict[str, list[dict[str, str]]],
            idlers: dict[str, list[str]],
            colors: dict[str, str],
            email_is_fresh: timedelta,
            emails_notify: str,
            tz: timezone,
            polling_time: int
    ) -> None:
        # to ping reacheability of a service, all different used
        # imap providers should be found.
        # keys are imap addresses, values are network states
        # imap.provider.domain = 'Up'/'Down'/'Waiting'
        self.providers = {}
        # init the helper class
        self.scr_output = ScreenOutput(work_with_xmail_inst, colors, email_is_fresh, emails_notify, tz)
        # if expected messages are used, init them too
        self.scr_output.set_expected_msg(expected_messages)
        # list of idents with missed expected messages
        self.idlers = []
        # all emails should be polled sometimes. Those, which have no
        # idlers should be polled to get it's state at all, those
        # who have idlers - to sync. timestamp will be checked
        # periodically to figure out if it's time to poll
        # keys are email idents
        self.xmails = {}
        for item in work_with_xmail_inst:
            self.xmails[item.ident] = {
                'xmail': item, # xmail instance
                'timestamp': 0,
                # will be turned to True if both idle and oauth2 are used
                'watch_token': False
            }
            # find all the different email providers by their
            # imap_address values
            if item.imap_address not in self.providers.keys():
                # set the network initial state
                self.providers[item.imap_address] = 'Down'
            # for those which require idling
            if item.ident in idlers.keys():
                # oauth2 is used only for gmail
                if isinstance(item, WorkWithGmail):
                    self.xmails[item.ident]['watch_token'] = True
                for mailbox in idlers[item.ident]:
                    self.idlers.append(
                        {
                            'xmail': item,
                            # idle protocol is silent, so if an error happens, a network
                            # issue or so, processes, listening for idle should be stopped
                            # and restarted when the issue isn't there anymore
                            # also it's used when have to restart idle after token update
                            'stop_event': Event(),
                            'idle_mailbox': mailbox,
                        }
                    )
        self.queue = Queue()
        # how often to poll mails
        self.polling_time = polling_time
        # timezone
        self.tz = tz

    def main(self) -> None:
        """The mail function which starts all necessary threads
        and the executes self.time_watcher function to be
        also usefull
        """
        # get emails initial state
        logger.debug('Init all emails')
        for val in self.providers:
            Thread(target=self.set_initial_state, args=(val,)).start()
        # start all idlers. We'll communicate with those threads via
        # Event()s, so we don't need to track their pointers
        for idler in self.idlers:
            Thread(target=self.wait_network_go_idle, args=(idler,)).start()
        # queue_listener doesn't require any control at all
        Thread(target=self.queue_listener).start()
        # and be usefull
        sleep(30)
        self.time_watcher()
        
    def set_initial_state(self, provider: str) -> None:
        """Waits until the service is reacheable and then requests
        messages for all emails of this provider. Also sets flag
        that the service is up

        Args:
            provider (str): imap server address
        """
        logger.debug(f'Initializing {provider}')
        provider_idents = []
        # get all WorkWith[G/ANY]mail of same provider
        for ident, xmail in self.xmails.items():
            if xmail['xmail'].imap_address == provider:
                provider_idents.append(ident)
        # if some thread is already pinging, no point to do it
        # as well, just sleep and wait
        while self.providers[provider] == 'Waiting':
            logger.debug(f'Waiting for network for {provider}')
            sleep(20)
        # if network is down, begin pinging
        if self.providers[provider] == 'Down':
            self.providers[provider] = 'Waiting'
            # each instance has wait_network, but one is enough
            self.xmails[provider_idents[0]]['xmail'].wait_network()
            self.providers[provider] = 'Up'
        # request messages for all emails when network is up
        logger.info(f'Provider {provider} is Up, requesting messages')
        for ident in provider_idents:
            self.request_messages(ident) 

    def wait_network_go_idle(self, idler: dict) -> None:
        """Assuming that if a network connection was lost, the
        initial state has to be reset anyway. So it's not necessary
        to ping server here too, we can just wait when set_initial_state
        set the flag

        Args:
            idler (dict): class instance containing xmail instance,
                            stop_event and monitorung mailbox
        """
        while True:
            # wait for a flag that network is up
            while not self.providers[idler['xmail'].imap_address] == 'Up':
                logger.debug(f'Idlук {idler["xmail"].ident} is waiting for network'
                f'of {self.providers[idler["xmail"].imap_address]} to go Up')
                sleep(20)
            # start idling
            idler['xmail'].go_idle(self.queue, idler['stop_event'], idler['idle_mailbox'])
            # if idler exited, then it happened because of stop_event
            # before restarting the idler, stop_event should be cleared
            idler['stop_event'].clear()
            logger.debug(f'Idling {idler["xmail"].ident} with mailbox {idler["idle_mailbox"]} is out')

    def request_messages(self, ident: str, next_try: bool=False) -> None:
        """Requests messages for one email. Sens reply into a queue,
        so it can be parsed by a listener

        Args:
            ident (str): account ident
            next_try (bool): if there was an error during message request,
                            we assume it's a minor network issue and give
                            it another try, but the next try should be the
                            last, and then waiting for the network.
                            Defaults to False
        """
        try:
            # this func can be called in separate threads, so we want to not
            # spam the server with frequent requests
            # if a request was done less than a minute ago, wait for a minute
            now = datetime.now(tz=self.tz).timestamp()
            if now - self.xmails[ident]['timestamp'] < 60:
                logger.debug(f'Too many requests for {ident}, waiting 60 seconds')
                sleep(60)
            # if we have fresher result, than at the moment of this request
            # was made, then the request isn't required
            if self.xmails[ident]['timestamp'] >= now:
                logger.debug(f'The timestamp for {ident}, is fresher, omitting request')
                return
            # reply template
            queue_reply = {
                'message_provider': 'msg_request',
                'ident': ident
            }
            # use more efficient method for gmail
            if self.xmails[ident]['xmail'].imap_address == 'imap.gmail.com':
                queue_reply['data'] = self.xmails[ident]['xmail'].get_messages_gmail_way()
            else:
                queue_reply['data'] = self.xmails[ident]['xmail'].get_messages()
            self.queue.put(queue_reply)
        except (ServerNotFoundError, gaierror):
            logger.debug(f'Server {self.xmails[ident]["xmail"].imap_address} was not found')
            # We should check out was it a coincidence or service uavailability
            # if it's up, then request messages again, otherwise mark provider as 'Down'
            if next_try or not self.xmails[ident]['xmail'].check_service_reacheable():
                self.put_provider_down(ident)
            else:
                self.request_messages(ident, True)

    def put_provider_down(self, ident: str) -> None:
        """Sets the provider state to 'Down', stops all idlers
        of this provider and shows th error on the screen. Then
        starts the init function which tries to set up all again

        Args:
            ident (str): account identifier
        """
        provider = self.xmails[ident]['xmail'].imap_address
        # check if it wasn't already done by some other thread
        if self.providers[provider] == 'Down':
            return
        # mark provider as Down
        self.providers[provider] = 'Down'
        logger.info(f'Provider {provider} is down')
        # stop idlers
        for idler in self.idlers:
            if idler['xmail'].imap_address == provider:
                idler['stop_event'].set()
                self.scr_output.output_no_data(idler['xmail'].ident, 'error')
        # try to init them again. This includes network await
        self.set_initial_state(provider)        

    def queue_listener(self) -> None:
        """Awaits for messages from the queue, parses them
        """
        # when there is no reason to request messages:
        # 1. There is just one message in the mailbox and we got 'seen'
        # 2. When there is no messages and we got and amount of 'EXPUNGE'
        # followed with one 'EXISTS'
        mailboxes_state = { idler['xmail'].ident: None for idler in self.idlers }
        while True:
            # get item
            queue_item = self.queue.get()
            now = datetime.now(tz=self.tz).timestamp()
            logger.info(f'Got message from the queue: {queue_item}')
            match queue_item['message_provider']:
                # message from an idling thread
                case 'idle':
                    # assuming we don't have to request messages by default
                    need_request_msg = False
                    # message contains a list of idle pushed events like 'EXISTS', 'seen' and so on
                    # if one message was read and it's the only event, we can
                    # tell the state of mailbox with certainty
                    if queue_item['message'] == ['seen'] and mailboxes_state[queue_item['ident']] == 1:
                        mailboxes_state[queue_item['ident']] = 0
                        # and show it
                        self.scr_output.ident_mails_to_zero(queue_item['ident']) 
                    else:
                        # there is also one case where there is no reason to request
                        # messages - when there are no unseen messages and any amount
                        # of 'EXPUNGE' events came, followed by one 'EXISTS'
                        expunge = queue_item['message'].count('EXPUNGE')
                        if not (mailboxes_state[queue_item['ident']] == 0 and
                            expunge > 0 and expunge == len(queue_item['message']) - 1):
                            # in all other cases - request messages
                            need_request_msg = True
                    if need_request_msg:
                        # just in case a request is already done, but a reply didn't come
                        # yet. Request will be done only if a previous request was done
                        # more than 3 seconds ago, so we assume it's enough to request
                        # and get reply
                        if now - self.xmails[queue_item['ident']]['timestamp'] > 3:
                            Thread(target=self.request_messages, args=(queue_item['ident'],)).start()
                # a message from a polling thread
                case 'msg_request':
                    # get new mailboxes state for one ident
                    new_mailboxes_state = self.scr_output.check_Result(queue_item['data'], queue_item['ident'])
                    # None means an error occured during messages request
                    if new_mailboxes_state is None:
                        # We should check out was it a coincidence or service uavailability
                        # if it's up, then request messages again
                        if self.xmails[queue_item['ident']]['xmail'].check_service_reacheable():
                            Thread(target=self.request_messages, args=(queue_item['ident'], True)).start()
                        # if it's not up, get all idlers of this provider and stop them
                        else:
                            Thread(target=self.put_provider_down, args=(queue_item['ident'],)).start()
                    else:
                        # refresh timestamp for this ident
                        self.xmails[new_mailboxes_state['ident']]['timestamp'] = now
                        # refresh idling mailboxes state
                        mailboxes_state[new_mailboxes_state['ident']] = new_mailboxes_state['msg_amount']

    def time_watcher(self) -> None:
        """Calls other functions which perform periodic
        state updates
        """
        # there is also a possibility that a pc was sleeping
        # assuming that we do periodical checks every minute
        # and if there a difference in 5 minutes, we can be sure
        # the system was sleeping
        prev_check = datetime.now(tz=self.tz).timestamp()
        while True:
            now = datetime.now(tz=self.tz).timestamp()
            # check if the system was sleeping more than 5 minutes
            if now - prev_check > 100:
                logger.info('Apparently the system was sleeping, trying to reset everything')
                # put all providers down so they will try to restart
                for xmail in self.xmails:
                    Thread(target=self.put_provider_down, args=(self.xmails[xmail]['xmail'].ident,)).start()
            else:
                # go through all accounts
                for ident, xmail in self.xmails.items():
                    # only if provder is UP
                    if self.providers[xmail['xmail'].imap_address] == 'Up':
                        # if it's time to poll
                        if now - xmail['timestamp'] > self.polling_time:
                            logger.info(f'Polling {xmail["xmail"].ident}')
                            # poll in a separate thread
                            Thread(target=self.request_messages, args=(ident,)).start()
                            # but set the timestamp so other threads can know that
                            # a request is already done
                            xmail['timestamp'] = now
                        # try to refresh token for those, who require it
                        if xmail['watch_token']:
                            xmail['xmail'].refresh_token()
                # refrash states
                self.scr_output.check_fresh_expired()
                self.scr_output.check_expected_expired()
            prev_check = now
            sleep(60)

def sendmessage(message: str='', timeout: str='0') -> None:
    """Sends a message to notification daemon in a separate process.
    urgency=critical makes a message stay until closed manually,
    for other message types types don't forget timeout"""

    icon = '/home/jastix/Documents/icons/gmail_256.png'
    subprocess.Popen(['notify-send', '-i', icon, '-t', timeout, 'email notificator error', message])


if __name__ == '__main__':
    # preparing logger. Creating a new instance because of
    # overlapping with imapclient
    logger = logging.getLogger('mylogger')
    if DEBUG:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '{asctime} [{levelname}]<{funcName}> {message}',
        datefmt='%Y-%m-%d %H:%M:%S',
        style='{'
    )
    handler = logging.StreamHandler()
    # # write log to the script dir
    # script_dir = path.dirname(path.realpath(__file__))
    # handler = logging.FileHandler(filename=path.join(script_dir, 'log.txt'))
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.debug('Start main')
    # prepare instances
    work_with_xmail_inst = []
    for mail in GOOGLE_LOGIN:
        work_with_xmail_inst.append(WorkWithGmail(
            **mail,
            imap_address=GOOGLE_IMAP['imap_address'],
            imap_conn_time=GOOGLE_IMAP['idle_conn_time'],
            tz=TZ
        ))
    for mail in ANYMAIL_LOGIN:
        work_with_xmail_inst.append(WorkWithAnyMail(
            **mail,
            tz=TZ
        ))
    dispatcher = Dispatcher(
        work_with_xmail_inst=work_with_xmail_inst,
        expected_messages=EXPECTED_MESSAGES,
        idlers=IDLERS,
        colors=COLORS,
        email_is_fresh=EMAIL_IS_FRESH,
        emails_notify=EMAILS_NOTIFY,
        tz=TZ,
        polling_time=POLLING_TIME
    )
    dispatcher.main()
            