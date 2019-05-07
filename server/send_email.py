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
    sender = 'lhyemailsender@gmail.com'
    server.login(sender, password)

    message = '''\
    <html>
        <h1>FAIL to find a MUD for this device</h1>
        <h2>But we generated a MUD like file based on the past activity of your device</h2>
        <p> Go to the router address </p>
        <a href = 'http://192.168.2.1:5000/'> My router: http://192.168.2.1:5000/ </a>
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



def case_two_alert(useraddr, matches, fileName):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()
    # password = raw_input('Type in your email password:')
    #password = getpass.getpass("Type in your email password: ")
    password = '1234567890s'
    sender = 'lhyemailsender@gmail.com'
    server.login(sender, password)

    message = '''\
    <html>
       <h1> Hi, we find a similar mud file with similarity {match} </h1>
       <h2> Is is a(n) {fileN}? </h2>
       <p> Go to ther router address </p>
       <a href = 'http://192.168.2.1:5000/?guess={guess}'> My router http://192.168.2.1:5000/?guess={guess} </a>
    </html>
    '''.format(match = matches, fileN = fileName, guess = fileName)

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
