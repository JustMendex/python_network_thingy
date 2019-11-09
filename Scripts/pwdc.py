import crypt
import pymysql

def showresult(result):
    print("Crypted Passwords\tDecrypted Passwords\n--------------------------------------------")
    for row in result:
        print(row[0] + "\t\t" + row[1])

def storedpwds():
    db = pymysql.connect('localhost','root','','pwdc')
    cursor = db.cursor()
    sql= """select * from pwdc"""
    try:
        cursor.execute(sql)
        result = cursor.fetchall()
    except Exception, e:
        print("error")
    showresult(result)

def add_result(cryptedpassword,word):
    db = pymysql.connect('localhost','root','','pwdc')
    cursor = db.cursor()
    sql = """insert into pwdc values(%s,%s)"""
    try:
        cursor.execute(sql,(cryptedpassword,word))
        db.commit()
    except:
        db.rollback()
    cursor.close()
    db.close()

def passwordmatching(cryptedpassword,dictfilelocation):

    dictionaryfile= open(dictfilelocation,'r')

    salt = cryptedpassword[0:2]

    for word in dictionaryfile.readlines():

        word = word.strip('\n')

        endresult = crypt.crypt(word,salt)

        if(cryptedpassword == endresult):

            print ("[+] password is: "+word + '\n')
            add_result(cryptedpassword,word)
            return

        else:

            pass
    print("Couldn't Crack the: "+cryptedpassword)

    return        

def main():
    decision = raw_input("[+] View stored passwords y/n ==>")
    if decision =="y":
        storedpwds()
    elif decision =="n":
        passfilelocation =raw_input("[+] Password File Location ==>  ")


        dictfilelocation =raw_input("[+] Dictionary File Location ==>  ")

        passwordfile = open(passfilelocation,'r')

        for line in passwordfile.readlines():

            if ":" in line:

                username=line.split(':')[0]

                cryptedpassword =line.split(':')[1].strip()

                print ("[*] Cracking Password For: "+username)

                passwordmatching(cryptedpassword,dictfilelocation)

            else:

                cryptedpassword=line.strip()

                print ("[*] Cracking Password For: "+cryptedpassword)

                passwordmatching(cryptedpassword,dictfilelocation)
    else:
        print("[-] Quitting")
        exit()

if __name__ == "__main__":

    main()
