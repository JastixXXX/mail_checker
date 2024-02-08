from datetime import timedelta, timezone

# ================ data to set =====================
GOOGLE_LOGIN = {
    # The CLIENT_SECRETS_FILE variable specifies the name of a file that contains
    # the OAuth 2.0 information for this application, including its client_id and
    # client_secret. Received from google cloud console
    'client_secrets_file': 'client_secret.json',
    # doesn't exist at the beginning, granted after user interaction
    'token_file': 'token.json',
    # If modifying these scopes, delete the file token.json.
    # 'scopes': ['https://www.googleapis.com/auth/gmail.readonly']
    'scopes': ['https://mail.google.com/'],
    'login': '<my_email>@gmail.com', # required for imap auth
    'mailboxes': ['INBOX', '<some_label1>', '<some_label2>']
}
# mail.ru не google, все сделано через жопу. OAuth2 для проверки
# почты идет нафиг за отсутствием внятной документации, плюсом
# ко всему нет возможности удаления своего приложения сразу после создания
# Заявка на удаление приложения отправлена администрации Платформы@Mail.Ru.
MAILRU_LOGIN = {
    'login': '<my_email>@mail.ru',
    'passwd': '<app_passwd>',
    'mailboxes': ['INBOX', 'INBOX/<some_inner_box>']
}
# expected messages. The script will monitor, if such didn't arrive and
# show with the color if it didn't. This message won't show up in the
# number of unseen. Done only for gmail
# pattern - <email addr>: <time trashold>
# If a message didn't come within midnight and the threshold, alarm comes
# example 'moy.leviy.yashik.nz@gmail.com: 12:00
EXPECTED_MESSAGES = {
    # 'moy.leviy.yashik.nz@gmail.com': '00:01',
    # 'terra_kassy@mail.ru': '02:25'
}
# colors for the text in css
COLORS = {
    'default': '#C0C0C0', # zero emails
    'white': '#FFFFFF', # for non colorized output
    'old_unseen': '#55A1FF', # sent more than two hours ago
    'new_unseen': '#19EF16', # sent within two hours
    'conn_error': '#E23030', # connection issues
    'msg_error': '#FF6B5C', # message retrieval issue
    'alarm': '#FD9A33' # an expected message didn't come
}
# how much time a new email counts as fresh
EMAIL_IS_FRESH = timedelta(hours=2)
# EMAIL_IS_FRESH = timedelta(minutes=3)
# a file to store the check result. Styled in css
EMAILS_NOTIFY = '/tmp/mails_notify'
# timezone, so we can properly distinguish how fresh a email is
TZ = timezone(timedelta(hours=3))
# ================ end of data to set ==============