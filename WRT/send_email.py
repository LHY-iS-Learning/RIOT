import smtplib
from email.mime.text import MIMEText
from email.header import Header


def alert(useraddr):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()
    # password = raw_input('Type in your email password:')
    #password = getpass.getpass("Type in your email password: ")
    password = '1234567890s'
    #sender = 'harrisonhuang1025@gmail.com' 
    sender = 'lhyemailsender@gmail.com'
    server.login(sender, password)

    message = '''\
    <html>
        <h1>FAIL to find a MUD for this device</h1>
        <p> Go to the router address </p>
        <a href = 'http://192.168.2.1:5000/'> My router </a>
    </html>
    '''
    # msg = MIMEText('FAIL to find a MUD for this device', 'plain', 'utf-8')
    msg = MIMEText(message, 'html')

    msg['Subject'] = Header('Alert from router', 'utf-8')
    msg['From'] = sender
    msg['To'] = useraddr
    try:
        server.sendmail(sender, useraddr, msg.as_string())
        print 'email sended'
    except:
        print 'fail to send email'
    finally:
        server.quit()