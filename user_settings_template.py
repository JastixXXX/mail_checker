from datetime import timedelta, timezone

# general settings
GOOGLE_IMAP = {
    'imap_address': 'imap.gmail.com',
    # idle drops after a while and requires reconnect. Experiments
    # showed that gmail keeps connection around this time
    'idle_conn_time': 14
}
# account settings. Only oauth2
GOOGLE_LOGIN = [
    {
        # The client_secrets_file variable specifies the name of a file that contains
        # the OAuth 2.0 information for this application, including its client_id and
        # client_secret. Received from google cloud console
        'client_secrets_file': 'gmail_creds/client_secret_one.json',
        # tiken doesn't exist at the beginning, granted after user interaction
        # just give it any name
        'token_file': 'gmail_creds/token_one.json',
        # If modifying these scopes, delete the file token.json.
        # 'scopes': ['https://www.googleapis.com/auth/gmail.readonly']
        'scopes': ['https://mail.google.com/'],
        'login': 'some_mail@gmail.com', # required for imap auth
        # in a case of gmail - it's labels
        'mailboxes': ['INBOX', 'from_myself'],
        # an identifier for mailbox. Emails are too long to show in the panel
        'ident': 'one',
    },
    {
        'client_secrets_file': 'gmail_creds/client_secret_two.json',
        'token_file': 'gmail_creds/token_two.json',
        'scopes': ['https://mail.google.com/'],
        'login': 'somemail_two@gmail.com',
        'mailboxes': ['INBOX'],
        'ident': 'two',
    },
]

# mail.ru не google, все сделано через жопу. OAuth2 для проверки
# почты идет нафиг за отсутствием внятной документации, плюсом
# ко всему нет возможности удаления своего приложения сразу после создания
# Заявка на удаление приложения отправлена администрации Платформы@Mail.Ru.

# Any login data, where app pasword is used
# gmail can be used this way too
ANYMAIL_LOGIN = [
    {
        'imap_address': 'imap.mail.ru',
        'idle_conn_time': 20,
        'login': 'somemail@some.com',
        'passwd': 'some_password',
        'mailboxes': ['INBOX', 'INBOX/ToMyself'],
        'ident': 'three',
    },
]

# imap idle is the method to get notifications from the server
# almost instantly after some event happened in the mailbox.
# one idler thread can connect to only one mailbox, so there will
# be several connections to monitor several folders. Unless we are
# dealing with gmail, which has '[Gmail]/All Mail' filder, where
# all mails land. Ofc it's not obligatory and we can connect to
# distonct folders-labels
IDLERS = {
    'one': ['[Gmail]/All Mail'],
    'two': ['INBOX'],
    'three': ['INBOX', 'INBOX/ToMyself']
}

# All mailboxes should be polled sometimes. Those which have no idlers
# should be polled to get data at all, those which have idlers -
# for the sake of syncing
POLLING_TIME = 1200

# this is for messages from some services. For example we have n services
# and want to get some status emails from them. And if such didn't arrive
# within 00:00 and stated time - then alarm color will be used for
# this account. Pattern is the next:
# ident:[{exp message1 data}, {exp message2 data}]
# ident is the identifier where a message should come.
EXPECTED_MESSAGES = {
    'one':[
        {
            'from': 'somemail_two@gmail.com',
            'get_until': '12:00',
            'subject': 'test subject'        
        },
        {
            'from': 'somemail_two@gmail.com',
            'get_until': '16:35',
            'subject': 'another subj'
        },
    ],
    'three':[
        {
            'from': 'somemail@some.com',
            'get_until': '18:00',
            'subject': 'Mail to myself'
        },      
    ]
}

# colors for the text in css
COLORS = {
    'default': '#C0C0C0', # zero emails or no connection was done yet
    'old_unseen': '#55A1FF', # sent more than EMAIL_IS_FRESH ago
    'new_unseen': '#19EF16', # sent within EMAIL_IS_FRESH time
    'error': '#E23030', # connection issues
    'alarm': '#FD9A33' # an expected message didn't come
}

# how much time a new email counts as fresh
EMAIL_IS_FRESH = timedelta(hours=2)

# a file to store the check result. Styled in css
EMAILS_NOTIFY = '/tmp/mails_notify'

# timezone, so we can properly distinguish how fresh a email is
TZ = timezone(timedelta(hours=3))
