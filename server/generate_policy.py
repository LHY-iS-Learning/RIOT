from policies_compare import compare_policy
from send_email import alert, case_two_alert

USER_ADDR = 'wh2417@columbia.edu'

if __name__ == "__main__":
    result, fileName, match = compare_policy()
    try:
        if result:
            case_two_alert(USER_ADDR, str(match), fileName)
        else:
            alert(USER_ADDR)
    except Exception as e:
       print e
       print "[INFO] send email to user"

