#!/home/$USER/Documents/Projects/email_check/venv/bin/python

# This script is meant to check out two email inboxes for
# unseen messages. It doesn't read them, only stores in a file
# the amount of unseen messages, changes the css style of a
# record in the file if a new message showed up recently.
# It can also fetch email headers. Not necessary now
# but can be usefull in the future.
# ====
# Program provides two classes to work with gmail and mail.ru
# each. Mail.ru uses app password login and email module to
# parse data. Gmail uses OAuth2 and googleapiclient to parse
# data. Though the first approach could be used for both sources
# of emails, the google one is more neat, so it stays. Probably
# mail.ru will be excluded in the future. Gmail also supports
# idle with no issues. The usage of idle for mailru was rejected
# because of multiple issues: bad imapclient behavior when
# timeout reached (endless cycle with 100% core ucage), imap
# messages with spaces in them which makes them not recognized
# by the library, an error if requesting mail headers when
# idle os on. So only polling. Thus expected messages are
# implemented only for gmail as well.
# ====
# imapclient is used for idle

import subprocess
import argparse
import logging
from user_settings import (
    GOOGLE_LOGIN, COLORS, EMAIL_IS_FRESH, 
    EMAILS_NOTIFY, EXPECTED_MESSAGES, 
    MAILRU_LOGIN, TZ
)
from os import path
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
from typing import Literal
from threading import Thread, Event
from queue import Queue
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header
from email.utils import parsedate_to_datetime
from socket import gaierror
from time import sleep
from requests import get, ConnectionError

DEBUG = True

@dataclass
class Onemail:
    From: str = ''
    Subject: str = ''
    Date: datetime|None = None

# a dataclass for result to return from any read mail function
# total_err if an error occured while getting message IDs
# msh_headers - parsed headers of successfully returned messages
# msg_err_count - if, for somre reason, an error occured while
# receiving data for a single message. Shouldn't happen because
# of batch request, only for all messages at once
@dataclass
class Result:
    total_err: bool = False
    msg_count: int = 0
    msg_headers: list[Onemail] = field(default_factory=list)
    msg_err: bool = False

class WorkWithGmail:

    def __init__(
        self,
        client_secrets_file: str,
        token_file: str,
        scopes: list[str],
        login: str,
        mailboxes: list[str]
    ) -> None:
        # first check files in the current working directory
        # if none, use the script file dir
        script_dir = path.dirname(path.realpath(__file__))
        if path.exists(client_secrets_file):
            self.client_secrets_file = client_secrets_file
        else:
            self.client_secrets_file = path.join(script_dir, client_secrets_file)
        if path.exists(token_file):
            self.token_file = token_file
        else:
            self.token_file = path.join(script_dir, token_file)
        self.scopes = scopes
        self.login = login
        self.mailboxes = mailboxes
        self.service = None
        self.creds = None

    def make_creds(self, stop_event: Event|None = None, critical_failure: Event|None = None) -> None:
        """Takes care of OAuth2 authentification. Checks the token
        existence and it's validity, because the autch token expires
        in one hour. If necessary, user is asked to allow access
        to his account. In a case of idle usage, takes stop_event to
        graceful restart in a case of network issue

        Args:
            stop_event (Event | None, optional): for a graceful idle
                        restart
            critical_failure (Event | None, optional): for a full stop

        Raises:
            TransportError: caused by network issues, for example
                        the network absense
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
                    logger.error('gmail: No network')
                    if stop_event is None:
                        raise TransportError
                    else:
                        # if idle is active, just signal teh network issues
                        stop_event.set()
                # all other are critical
                except Exception as e:
                    logger.error('An error occured during a Refresh() request')
                    if critical_failure is None:
                        raise e
                    else:
                        critical_failure.set()
                        raise e
            else:
                # if no client_secret then no point to continue
                # raise the error which won't be intercepted
                if not path.exists(self.client_secrets_file):
                    critical_failure.set()
                    logger.error('client_secret is absent')
                    raise FileNotFoundError('client_secret is absent')
                flow = InstalledAppFlow.from_client_secrets_file(self.client_secrets_file, self.scopes)
                try:
                    self.creds = flow.run_local_server(port=0, timeout_seconds=60)
                # if connection wasn't established, then when timeout is reached, we'll get
                # authorization_response = wsgi_app.last_request_uri.replace("http", "https")
                # AttributeError: 'NoneType' object has no attribute 'replace'
                except AttributeError:
                    logger.error('gmail: No network')
                    # it's not a mistake. AttributeError doesn't explain what happened
                    # for a caller, but it's the network absense
                    if stop_event is None:
                        raise TransportError
                    else:
                        stop_event.set()
                except Exception as e:
                    logger.error('An error occured during the user access request')
                    if critical_failure is None:
                        raise e
                    else:
                        critical_failure.set()
                        raise e
            # Save the credentials for the next run
            with open(self.token_file, 'w') as token:
                logger.debug('gmail: Saving new access token')
                token.write(self.creds.to_json())

    def go_idle(self, queue: Queue, stop_evnt: Event, critical_failure: Event|None = None) -> None:
        """Connects to the gmail server, establishes idle. Gmail drops
        connection in 10 minutes, so every 9 minutes we reestablich it.
        Every 60 seconds the stop_event is checked, because in a case
        of network loss, the connection won't signal anyhow, neither
        it will reestablish by itself. And since it interrupts anyway
        every 60 seconds at least, it also works as a timer for queue
        consumer.

        Args:
            queue (Queue): a queue to put events to. Two types of
                        events are possible - 'gmail' (push message
                        via idle) and 'tick'
            stop_evnt (Event): a way to gracefully stop the thread
        """
        logger.info('gmail: Starting idle')
        self.make_creds(stop_evnt, critical_failure)
        with IMAPClient('imap.gmail.com') as client:
            try:
                client.oauth2_login(self.login, self.creds.token)
                client.select_folder('[Gmail]/All Mail')
                # to count loop runs to reset idle
                counter = 9
                client.idle()
                while not stop_evnt.is_set():
                    # reset idle if it's time
                    if counter == 0:
                        # if the connection is already dropped by the server, an attempt to
                        # cancel it will cause 'imaplib.IMAP4.abort: socket error: EOF'
                        logger.debug('gmail: Stopping idle by counter')
                        client.idle_done()
                        counter = 9
                        logger.debug('gmail: Starting idle by counter')
                        client.idle()
                    # leave the waiting state every minute to check the stop event
                    responses = client.idle_check(timeout=60)
                    # the message doesn't matter. For the sake of sync we'll request
                    # all the unseen messages anyway. So we just signal
                    if responses:
                        logger.info(f'gmail: Got message {responses}')
                        queue.put('gmail')
                        counter = 9
                    # if timeout is exceeded and nothing came from the server
                    # we send a tick in a queue, simply because the loop is run
                    # every minute, so we can work an a not very accurate timer
                    else:
                        queue.put('tick')
                        counter -= 1
                        logger.debug(f'gmail: Counter tick {counter}')
                    # to prevent a lot of message fetches in a case user
                    # just manages his inbox
                    # sleep(1)
                # stop by the event
                else:
                    logger.info('gmail: Stopping idle by stop event')
                    client.idle_done()
            except IMAP4.abort:
                logger.error('gmail: Received an IMAP4.abort exception')
            finally:
                stop_evnt.set()
                # out of turn tick so the make_file_worker can do all the
                # checks instead of endless queue waiting
                queue.put('tick')

    def get_messages(self, q_custom: str='', no_metadata: bool=False) -> Result:
        """Requests list of email IDs from gmail. If no_metadata=True,
        then just counts the amount of those IDs, i.e. the amount of
        messages. If no_metadata=False, then fetches the metadata for
        each email and returns it's parsed headers in Result as well

        Args:
            no_metadata (bool, optional): whether or not request
                        metadata for each email. Defaults to False.

        Returns:
            Result: a dataclass containing requested mesage data or errors
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
                result.msg_err = True
            else:
                msg_list.append(response)

        logger.debug('gmail: Requesting message IDs')
        result = Result() # container for results
        msg_list = [] # for raw emails
        try:
            self.make_creds() # always check if still valid
            # Call the Gmail API
            service = build('gmail', 'v1', credentials=self.creds)
            # prepare a part of query for mailboxes to request mails from
            # if there wasn't any custom qerry
            if not q_custom:
                q_custom = ' OR '.join([ 'label:' + mailbox for mailbox in self.mailboxes ]) + ' AND is:unread'
            # get message ids
            results = service.users().messages().list(userId='me',q=q_custom).execute()
            # now, depending on no_metadata flag we either just count the amount
            # of message IDs and return, or prepare the batch request for messages metadata
            result.msg_count = len(results.get('messages', []))
            logger.info(f'gmail: Got IDs for {result.msg_count} messages')            
            if no_metadata or result.msg_count == 0:
                return result
            else:
                logger.debug('gmail: Requesting messages data')
                # Use the batchGet method to retrieve headers for multiple messages
                batch = service.new_batch_http_request()
                # prepare batch request to get each message metadata by it's ids
                # if no format specified, full messages will be retrieved
                for message_id in results.get('messages', []):
                    batch.add(service.users().messages().get(
                        userId='me', id=message_id['id'], format='metadata', metadataHeaders=['subject','date','from']
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
                            ready_header.Date = datetime.now(tz=TZ)
                        continue
                    setattr(ready_header, header_name, value)
                result.msg_headers.append(ready_header)
            logger.debug('gmail: Got messages data')            
        except (HttpError, ServerNotFoundError, TransportError) as error:
            logger.error(f'gmail: A network error happened {error}')
            result.total_err = True
        return result
    
    def show_all_labels(self) -> None:
        """Lists all labels (folders in other mail providers) existing
        on the account
        """
        self.make_creds() # always check if still valid
        logger.debug('gmail: Labels requested')
        try:
            # Call the Gmail API
            service = build('gmail', 'v1', credentials=self.creds)
            # get the list of inbox directories
            labels= service.users().labels().list(userId='me').execute().get('labels', None)
            if labels is not None:
                print(labels)
        except (HttpError, ServerNotFoundError) as error:
            logger.error(f'gmail: An error occurred: {error}')

    @staticmethod
    def check_service_reacheable() -> bool:
        """Requests an html page from gmail which shows
        that the service is reacheable

        Returns:
            bool: The service (and the network) is reacheable
                        'True', or not 'False'
        """
        try:
            get("https://gmail.com", timeout=5)
            logger.debug('gmail: Network is ok')
            return True
        except ConnectionError:
            logger.debug('gmail: Network failed')
            return False
        
    def wait_network(self) -> None:
        """Waits for the service to be reacheable, constantly
        increasing the wait interval between attempts, untill
        it's a few minutes. Method is done when the service
        is ready
        """
        logger.debug('gmail: Start waiting')
        wait_time = 10
        while not self.check_service_reacheable():
            if wait_time < 159:
                wait_time = wait_time * 2
            sleep(wait_time)
        logger.debug(f'gmail: End waiting with wait_time = {wait_time}')

class WorkWithMailru:

    def __init__(self, login: str, passwd: str, mailboxes: str) -> None:
        self.login = login
        self.passwd = passwd
        self.mailboxes = mailboxes
        self.loggedin_client = None

    def _login_client(self) -> None:
        """Logging in via imapclient with app password
        """
        self.loggedin_client = IMAPClient('imap.mail.ru')
        try:
            self.loggedin_client.login(self.login, self.passwd)
        # doesn't matter what error. We can't get messages
        # so can't continue
        except Exception as e:
            logger.error('An error occured during a login attempt')
            raise e

    def _logout_client(self) -> None:
        """Logging out. If server already closed the connection
        then do nothing
        """
        if self.loggedin_client is not None:
            # jut trying to logout. If server already closed the
            # connection then whatever
            try:
                self.loggedin_client.logout()
                self.loggedin_client = None
            except Exception as error:
                logger.debug(f'mailru: An error occured {error}')

    def show_all_folders(self) -> None:
        """Prints all folders on the account
        """
        self._login_client()
        logger.debug('mailru: Folders requested')
        print(self.loggedin_client.list_folders())
        self._logout_client()

    def get_messages(self, search_val: list=['UNSEEN'], no_metadata: bool=False) -> Result:
        """Requests list of email IDs from mailru. If no_metadata=True,
        then just counts the amount of those IDs, i.e. the amount of
        messages. If no_metadata=False, then fetches the metadata for
        each email and returns it's parsed headers in Result as well

        Args:
            search_val (list, optional): the search criteria, valid
                        for imapclient. Defaults to ['UNSEEN']
            no_metadata (bool, optional): whether or not request
                        metadata for each email. Defaults to False.

        Returns:
            Result: a dataclass containing requested mesage data or errors
        """
        logger.debug('mailru: Requesting message IDs')
        result = Result() # prepare the result object
        uids = {} # uids of messages which headers we'll fetch
        # get unseen uids for all requested mailboxes
        try:
            self._login_client() # always do it
            for mailbox in self.mailboxes:
                self.loggedin_client.select_folder(mailbox)
                uids[mailbox] = self.loggedin_client.search(search_val)
                result.msg_count += len(uids[mailbox])
            logger.info(f'mailru: Got IDs for {result.msg_count} messages') 
            # now, depending on no_metadata flag we either just count the amount
            # of message IDs and return, or prepare the batch request for messages metadata
            if no_metadata or result.msg_count == 0:
                return result
            else:
                result.msg_err = True
                logger.debug('mailru: Requesting messages data')
                messages = {} # for raw responce for messages headers
                # mailru hasn't all mail analog, so we have to check all
                # mailboxes of interest and get mail uids
                for mailbox in self.mailboxes:
                    self.loggedin_client.select_folder(mailbox)
                    # Fetch email headers for the matching emails
                    messages.update(self.loggedin_client.fetch(uids[mailbox], ['BODY.PEEK[HEADER.FIELDS (FROM DATE SUBJECT)]']))
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
                        tmp_result_item.Date = datetime.now(tz=TZ)
                    # add the header to the total result
                    result.msg_headers.append(tmp_result_item)
                logger.debug('mailru: Got messages data') 
                result.msg_err = False
        except (IMAP4.abort, gaierror) as error:
            logger.error(f'mailru: Received an error: {error}, probably network issue')
            result.total_err = True
        self._logout_client()
        return result

class ScreenOutput:
    def __init__(
            self,
            work_with_xmail_inst: dict,
            queue: Queue|None = None,
            stop_event: Event|None = None,
            color: bool = True,
            noalarm: bool = False
    ) -> None:
        # a dict containing the provider names and keys and
        # WorkWith... instances as values
        self.work_with_xmail_inst = work_with_xmail_inst
        # queue to receive idle and timer notifications
        self.queue = queue
        # an event to stop worker
        self.stop_event = stop_event
        # make colorized output or not
        self.color = color
        # a dictionary of expected mails with datetime objects
        self.expected_msg = {}
        # in a case an expected message didn't come the script
        # can be started without notifications about the old alarms
        self.noalarm = noalarm
        # is a case a script withh work after midnight, expected
        # messages should be reset
        self.day = datetime.now(tz=TZ).day
        # a missed expected message, alarm
        self.galarm = False
        # messages to keep checking for. Those which threshold
        # is already reached are expunged
        self.pending_for_alarm = {}

    def set_initial_state(self) -> None:
        """These variables have to be reset after the network loss.
        To make it easy they are wrapped in a function
        """
        logger.debug('Setting defaults')
        # data, stored in notify file. It should be kept because we monitor
        # two mail sources, but storing the result in one file. One part
        # shouldn't implact another.
        self.notify_file_str = {
            'gmail_color': COLORS['default'],
            'gmail_unseen_num': '-',
            'mailru_color': COLORS['default'],
            'mailru_unseen_num': '-',
        }      
        # a dict to store fresh messages within EMAIL_IS_FRESH time
        # pattern <mail provider>: <time>
        self.fresh_messages = {}

    def make_file(
        self,
        mail_server: Literal['gmail', 'mailru'],
        unseen_mail_num: int|str|None=None,
        color: Literal['old_unseen', 'new_unseen', 'conn_error', 'msg_error', 'alarm', 'default', 'white']|None=None
    ) -> None:
        """Writes down the properly styled string in a file. Changes only
        half a string, taking the other half from self.notify_file_str. Also
        takes there all arguments, which are not given

        Args:
            mail_server (Literal['gmail, 'mailru']): which half to change, also a key
                        for self.notify_file_str dict
            unseen_mail_num (int | str, optional): the number to show
            color (Literal['old_unseen', 'new_unseen', 'conn_error', 'msg_error',
                        'alarm', 'default','white'], optional): the color for letters
                        to show. Actual hex numbers are taken from COLORS dict
        """
        logger.debug(f'Changing {mail_server} part')
        # only these two options are allowed
        if not mail_server in ['gmail', 'mailru']:
            return
        # store new data in notify_file_str so it reflects the file
        if unseen_mail_num is not None:
            self.notify_file_str[mail_server + '_unseen_num'] = unseen_mail_num
        if color is not None:
            self.notify_file_str[mail_server + '_color'] = COLORS[color]
        # writing down the file with proper styling
        with open(EMAILS_NOTIFY, 'w') as f:
            f.write(
                f'<txt> <span foreground="{self.notify_file_str["gmail_color"]}">'
                f'gmail: {self.notify_file_str["gmail_unseen_num"]}</span> | '
                f'<span foreground="{self.notify_file_str["mailru_color"]}">'
                f'mailru: {self.notify_file_str["mailru_unseen_num"]}</span> </txt>'
            )

    def set_expected_msg(self, expected_msg: dict) -> None:
        """Takes human defined EXPECTED_MESSAGES and turns time
        into a datetime object. Forms pending_for_alarm containing
        the messages to await for in incoming messages. If noalarm,
        those expected messages, which already reached their
        threshold are excluded.

        Args:
            expected_msg (dict): <email@addres: time>. Await an
                        email from 'email@addres' until 'time'
        """
        # turn EXPECTED_MESSAGES threshold into a datetime object
        # only if expected exist and colorized output is taken
        if expected_msg and self.color:
            logger.debug('Formatting EXPECTED_MESSAGES')
            now = datetime.now(tz=TZ)# current time
            for k, v in expected_msg.items():
                user_time = datetime.strptime(v, "%H:%M").time() # convert string
                # combine today date and human defined tine
                self.expected_msg[k] = datetime.combine(now.date(), user_time).replace(tzinfo=TZ)
                # if noalarm is not set - pending_for_alarm will be a simple
                # copy of expected_msg. Otherwise only those will be kept
                # which threshold is infront
                if not self.noalarm or self.expected_msg[k] > now:
                    self.pending_for_alarm[k] = self.expected_msg[k]

    def _check_expected_messages(
            self, message_list: Result|None=None,
            request_msg: bool=False,
        ) -> None:
        """The function wotks in three modes:
        1. got request_msg=True. It's for the first launch and the function
        requests messages itself to check if an expected message came already.
        2. message_list only. This is the most common mode. The function checks
        if new messages have an expected one and if the threshold is reached
        3. Neither is provided. In this mode the function only checks if it's
        later than the threshold or not. If alarm is set, no further checks
        will be done

        Args:
            message_list (Result | None, optional): already received list of messages
            request_msg (bool, optional): a flag to request messages
        """
        # if there are any messages to wait for
        if self.pending_for_alarm:
            logger.debug('Start')
            now = datetime.now(tz=TZ)
            # if the midnight came, we should change the date part
            # of expected messages and reenable all of them to pending
            if now.day != self.day:
                logger.debug('Day changed, resetting expected messages')
                self.day = now.day
                for k, v in self.expected_msg.items():
                    self.expected_msg[k] = v + timedelta(days=1)
                self.pending_for_alarm = self.expected_msg.copy()
            # if there are no messages provided, it means it's either a
            # fresh launch of the script or a tick
            if message_list is None:
                # if no messages and no flag to request messages, it's
                # a tick. So the method only checks if any of the thresholds
                # in pending_for_alarm is reached
                if not request_msg:
                    now = datetime.now(tz=TZ)
                    for k, v in self.pending_for_alarm.items():
                        if now > v:
                            # alarm is alarm, there is nothing to keep checking
                            self.galarm = True
                            self.pending_for_alarm.clear()
                            logger.debug('A tick check set the alarm')
                            return
                    return
                # gmail requires format after:timestamp, and to get all
                # messages since today midnight we do. int removes the dot
                yesterday = int(datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
                message_list = self.work_with_xmail_inst['gmail'].get_messages(q_custom=f'after:{yesterday}')
            remove_pending = []
            # if an awaited message arrived, remove it from pending
            for k, v in self.pending_for_alarm.items():
                for header in message_list.msg_headers:
                    if k in header.From and header.Date.date() == now.date():
                        remove_pending.append(k)
                        break
                # if there is no message we were looking for
                else:
                    # the threshold is already behind
                    if v < datetime.now(tz=TZ):
                        self.galarm = True
                        self.pending_for_alarm.clear()
                        logger.debug('Alarm is set')
                        return
            for item in remove_pending:
                logger.debug(f'{item} is removed from pending')
                del self.pending_for_alarm[item]

    def _check_fresh_expired(self) -> None:
        """Compares the time in fresh_messages with the current
        time and if it's older than EMAIL_IS_FRESH value, then
        removes such from the accounting and changes the output
        color back to old_unseen
        """
        # if fresh messages exist at all, we should check if they
        # are still fresh
        if self.fresh_messages:
            now = datetime.now(tz=TZ)
            # check if a such message was received longer than EMAIL_IS_FRESH ago
            remove = [] # for keys to remove if message is no longer fresh
            for k, v in self.fresh_messages.items():
                if (now - v) > EMAIL_IS_FRESH:
                    # put color to normal
                    self.make_file(k, color='old_unseen')
                    remove.append(k) # store key
                    logger.debug(f'Fresh {k} expired')
            # remove outdated keys from fresh_messages
            for k in remove:
                del self.fresh_messages[k]
    
    def _check_Result(self, result: Result, provider: str) -> None:
        """This method is called to analyze the Result instance.
        Does mostly the same things regardless of the mode (idle
        or polling)

        Args:
            result (Result): the result instance. Contains data with
                        results of messages request
            provider (str): 'gmail' or 'mailru'
        """
        # if a total error occured, even the unseen mails amount
        # wasn't retrieved. Show connection error color and no mail num
        if result.total_err:
            self.make_file(provider, color='conn_error')
            logger.debug('Total error')
            # if stop_event is provided, then we are dealing with the
            # idle mode. Set the stop even to notify all threads to restart
            # but only if an error occured in gmail part. mailru is way too
            # unreliable
            if self.stop_event is not None and provider == 'gmail':
                self.stop_event.set()
            return
        # next importance is message retrieval error. If it happened
        # we can't make conclusions about alarm or fresh emails,
        # because we can't analyze headers, but we got the amount
        if result.msg_err:
            self.make_file(provider, unseen_mail_num=result.msg_count, color='msg_error')
            logger.debug('Message error')
            return
        # next importance is alarm. only for gmail
        if provider == 'gmail':
            # if alarm is on, no checks needed
            if self.galarm:
                self.make_file('gmail', unseen_mail_num=result.msg_count, color='alarm')
                return
            self._check_expected_messages(message_list=result)
            # if alarm showed up afte rthis check
            if self.galarm:
                self.make_file(provider, unseen_mail_num=result.msg_count, color='alarm')
                return
        # Now check for messages, fresher than EMAIL_IS_FRESH. Makes
        # sense only if msg_count more than zero
        if result.msg_count > 0:
            now = datetime.now(tz=TZ)
            # now depending on the mode (idle or polling)
            # conclude by the stop_event presense
            # so, if polling
            if self.stop_event is None:
                for msg in result.msg_headers:
                    # look for a frewsh message
                    if (now - msg.Date) < EMAIL_IS_FRESH:
                        self.make_file(provider, unseen_mail_num=result.msg_count, color='new_unseen')
                        return
                # if no fresh found
                self.make_file(provider, unseen_mail_num=result.msg_count, color='old_unseen')
                return
            # for idle we have to store the freshest message in
            # fresh_messages for periodic checks
            else:
                freshest_msg_date = None
                for msg in result.msg_headers:
                    # if a message not only unseen but also freah
                    if (now - msg.Date) < EMAIL_IS_FRESH:
                        # find freshest
                        if freshest_msg_date is None:
                            freshest_msg_date = msg.Date
                        elif freshest_msg_date < msg.Date:
                            freshest_msg_date = msg.Date
                # if there is a fresh message, save it's datetime, color new_unseen
                if freshest_msg_date is not None:
                    logger.debug(f'New fresh for {provider} set')
                    self.fresh_messages[provider] = freshest_msg_date
                    self.make_file(provider, unseen_mail_num=result.msg_count, color='new_unseen')
                # if there are no fresh messages among unseen - remove the
                # key from accounting in fresh_messages and color old_unseen
                else:
                    self.fresh_messages.pop(provider, None)
                    self.make_file(provider, unseen_mail_num=result.msg_count, color='old_unseen')
                return
        # if no unseen messages, color default
        self.make_file(provider, unseen_mail_num=0, color='default')     

    def _no_color_make_file(self, provider: str) -> None:
        """For non colorized output. Simply requests the unseen uids.
        If an error occures, shows '-' as messages amount and default
        color. If there are messages - shows white. If no messages
        and no errors - shows 0 and default.

        Args:
            provider (str): 'gmail' or 'mailru'
        """
        logger.debug('Start')
        # request messages with no headers, we won't analyze it
        result = self.work_with_xmail_inst[provider].get_messages(no_metadata=True)
        # if a total error occured, even the unseen mails amount
        # wasn't retrieved. Show connection error color and no mail num
        if result.total_err:
            self.make_file(provider, unseen_mail_num='-', color='default')
            logger.debug('Total error')
            return
        # Now check for messages, fresher than 2h. Makes sense only
        # if msg_count more than zero
        if result.msg_count > 0:
            self.make_file(provider, result.msg_count, 'white')
            logger.debug('Message error')
            return
        self.make_file(provider, unseen_mail_num=0, color='default')  

    def make_file_worker(self, mailru_poll_interval: timedelta = timedelta(minutes=14)) -> None:
        """Processes the data, received from the idle thread via
        queue. Also makes polling for mailru provider, because
        idle for it was rejected as causing a lot of problems.

        Args:
            mailru_poll_interval (timedelta, optional): how often to poll
                        mailru

        Raises:
            ValueError: if queue or stop_event aren't set, it's not
                        possible to work without them
        """
        def get_item() -> str:
            """If mailru_poll_interval elspsed, returns 'mailru' for
            polling. If it didn't elapse yet, requests a queue item,
            which will be either 'tick' or 'gmail' and comes not
            later than in one minute

            Returns:
                str: 'mailru', 'gmail' or 'tick'
            """
            nonlocal mailru_checked
            if (now := datetime.now(tz=TZ)) - mailru_checked > mailru_poll_interval:
                logger.debug('Polling mailru')
                mailru_checked = now
                return 'mailru'
            else:
                return self.queue.get() # 'gmail' or 'tick'
                
        if self.queue is None or self.stop_event is None:
            raise ValueError('You forgot to set Queue and Event for idle mode')
        logger.info('Starting thread make_file worker')
        # to compare for mailru_poll_interval
        mailru_checked = datetime.now(tz=TZ)
        # to request initial states
        queue.put('mailru')
        queue.put('gmail')
        if self.color:
            # first launch. Check if alarm is needed if noalarm not set
            if not self.noalarm:
                self._check_expected_messages(request_msg=True)
            while not self.stop_event.is_set():
                item = get_item()
                logger.debug(f'Got {item} from the queue')
                # check only colors state. fresh to not fresh, no alarm to alarm
                # but only if colorized output
                if item == 'tick':
                    if not self.galarm:
                        self._check_expected_messages()
                        if self.galarm:
                            self.make_file('gmail', unseen_mail_num=self.notify_file_str['gmail_unseen_num'], color='alarm')
                            continue
                        self._check_fresh_expired()
                    continue
                self.fresh_messages.pop(item, None)
                result = self.work_with_xmail_inst[item].get_messages()
                self._check_Result(result, item)
        else:
            # for non colorized output
            while not self.stop_event.is_set():
                item = get_item()
                # ticks are used only for color change, thus
                # aren't used in non colorized case
                if item == 'tick':
                    continue
                self._no_color_make_file(item)

    def make_file_poller(self, interval: int) -> None:
        """Polls messages from the server with 'interval'
        intervals for both providers

        Args:
            interval (int): seconds between pollings
        """
        logger.info('Starting make_file poller')
        if self.color:
            # for initial state. If 'noalarm = False' and
            # there were expected messages among all messages
            # today, no alarm will be raised
            if not self.noalarm:
                self._check_expected_messages(request_msg=True)
            while True:
                # for both providers
                for item in ['gmail', 'mailru']:
                    # request and analyze messages
                    result = self.work_with_xmail_inst[item].get_messages()
                    self._check_Result(result, item)
                logger.debug('Sleeping')
                sleep(interval)
        else:
            # for non colorized output the Result checks isn't requeired
            while True:
                for item in ['gmail', 'mailru']:
                    self._no_color_make_file(item)
                logger.debug('Sleeping')     
                sleep(interval)

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
    # handler = logging.StreamHandler()
    # write log to the script dir
    script_dir = path.dirname(path.realpath(__file__))
    handler = logging.FileHandler(filename=path.join(script_dir, 'log.txt'))
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    parser = argparse.ArgumentParser()
    # add three optional arguments
    # use idle for gmail. both polling by default
    parser.add_argument('--idle', type=bool, default=True)
    # no alarm if we want to skip checks for EXPECTED_MESSAGES
    # thresholds happened before the script launch
    parser.add_argument('--noalarm', type=bool, default=True)
    # colorized output. ON by default
    parser.add_argument('--color', type=bool, default=True)
    logger.debug('Start main')
    args = parser.parse_args()
    # catch errors which aren't intercepted
    try:
        # prepare instances
        gmail = WorkWithGmail(**GOOGLE_LOGIN)
        mailru = WorkWithMailru(**MAILRU_LOGIN)
        # network can be absent, especially after turning on pc
        # wait until gmail will reply. No need to ask both, gmail is reliable
        gmail.wait_network()
        if not args.idle:
            make_file = ScreenOutput({'gmail': gmail, 'mailru': mailru}, color=args.color, noalarm=args.noalarm)
            make_file.set_initial_state()
            make_file.set_expected_msg(EXPECTED_MESSAGES)
            make_file.make_file_poller(870)
        else:
            # prepare objects to control and communucate threads
            queue = Queue()
            stop = Event()
            # prepare ScreenOutpu instance
            make_file = ScreenOutput({'gmail': gmail, 'mailru': mailru}, queue, stop, color=args.color, noalarm=args.noalarm)
            # set it's defaults
            make_file.set_initial_state()
            # add EXPECTED_MESSAGES, optional
            make_file.set_expected_msg(EXPECTED_MESSAGES)
            loop = True
            start_workers = None
            # a flag to prevent the loop from running
            # getting set if a serious error happened
            critical_fail = Event()
            while loop and not critical_fail.is_set():
                try:
                    # a protection against calling mail servers too often
                    # due to errors. Ensures at least 10 minutes
                    if start_workers is not None:
                        # if we are here it also eman't it's not the first loop run
                        # so we can check why we are here
                        # workers joined likely because network issues, check net
                        gmail.wait_network()
                        stop.clear()
                        delay = datetime.now() - start_workers
                        min_delay = timedelta(minutes=10)
                        if delay < min_delay:
                            sleep((min_delay - delay).total_seconds())
                    logger.debug('Main cycle round')
                    # set the queue consumer - the function which changes file
                    queue_consumer = Thread(target=make_file.make_file_worker)
                    # set gmail idle thread
                    gmail_idle = Thread(target=gmail.go_idle, args=(queue, stop, critical_fail))
                    # clear in a case it's a restart
                    queue.queue.clear()
                    start_workers = datetime.now()
                    # start workers
                    queue_consumer.start()
                    gmail_idle.start()
                    # wait for them to finish. They finish only if the stop event
                    # was set, or an uncauched exception happened
                    gmail_idle.join()
                    queue_consumer.join()
                    logger.debug('All worker threads are done')
                except KeyboardInterrupt:
                    logger.debug('Interrupted')
                    stop.set()
                    loop = False
    # show them on the screen
    except Exception as e:
        sendmessage(message=str(e))
        logger.debug(f'An error: {e}')
    # show the error
    make_file.make_file('gmail', '-', 'conn_error')
    make_file.make_file('mailru', '-', 'conn_error')
            