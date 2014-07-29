"""
Parser for http://www.ntdsxtract.com/ output

Expects format:

Record ID:           <number>
User name:           <name>
User principal name: 
SAM Account name:    <name>
SAM Account type:    <name>
GUID: <GUID>
SID:  <SID>
When created:         <datetime>
When changed:         <datetime>
Account expires:      Never
Password last set:    <datetime>
Last logon:           <datetime>
Last logon timestamp: <datetime>
Bad password time     <datetime>
Logon count:          <number>
Bad password count:   <number>
User Account Control:
NORMAL_ACCOUNT
PWD Never Expires
Ancestors:
<name> 
Password hashes:
<AccountName:hash:::>
Password history:
<AccountName_nthistory:hash:::>

"""
#INPUT FILES

NTDS_rawdog = "raw_ntds_dump.txt"
LM_plus_plain = "LM_hash_plus_plain.txt"
NTLM_plus_plain = "NTLM_hash_plus_plain.txt"

# OUTPUT FILES
USER_PASS = "USER_PLAIN.txt"
PASSES = "PASS_PLAIN.txt"

# given a list of ordered lines returns a dictionary for a user account
def parse_account(raw_record):
   
   in_password_hashes = False
   in_password_history = False
   
   sam_account_name = None
   user_name = None
   lm_hash = None
   ntlm_hash = None
   ntlm_history = []
   lm_history = []

   for line in raw_record:
       # hack to ignore line without colon delimiter
       if "Bad password time" in line:
           continue
       
       if "SAM Account name:" in line:
           sam_account_name = line[line.find(":")+1:].strip()
       if "User name:" in line:
           user_name = line[line.find(":")+1:].strip()
           
           
       if "Password hashes:" in line:
           in_password_hashes = True
           continue
       
       
       if in_password_hashes == True:
           #we're working with an indented hash
           if "Password history:" in line:
               in_password_history = True
               in_password_hashes = False
               continue
           else:
               pieces = line.split(":")
               t = pieces[0]
               hsh = pieces[1]
               
               if hsh.find("$NT$") == 0:
                   ntlm_hash = hsh.split("$NT$")[1]
               else:
                   lm_hash = hsh
               
               #print(line)
               #parse hashes here
       
       if in_password_history == True:
           
           # we're at the end of the record, 
           # so everything else is going to be a history entry
           pieces = line.split(":")
           if "nthistory" in pieces[0]:
               hsh = pieces[1].split("$NT$")[1]
               ntlm_history.append([pieces[0],hsh])
           elif "lmhistory" in pieces[0]:
               lm_history.append([pieces[0],pieces[1]])
           else:
               # lolwat
               pass
           
   return {"sam_account_name":sam_account_name, "user_name":user_name, "lm_hash":lm_hash, "ntlm_hash":ntlm_hash, "ntlm_history":ntlm_history, "lm_history":lm_history, "lm_plain": None, "ntlm_plain":None}

# given an ntds.dit seperate records from each other and keep everything in order
# return a list of lists (each list is a collection of lines that looks like a record)
def split_record_lines(raw_lines):
   raw_records = []
   raw_record = []
   in_records = False
   new_record_header = False
   record_count = 0
   
   for line in raw_lines:
       t = line.strip()
       
       if t.find("Record ID:") == 0:
           record_count += 1
           new_record_header = True
           # this takes care of the junk at the top of the file
           if in_records == False:
               in_records = True
       else:
           new_record_header = False

       if in_records:
           if new_record_header == True:
               # if we just hit the first record, 
               # we won't have any lines stored from a previous record
               # so just append it and move on to the next line
               if len(raw_record) == 0:
                   raw_record.append(t)
               # if we ended up here with a full raw_record list
               # it needs to be saved and cleared 
               # then have the Record ID line from our new record added to it
               else:
                   raw_records.append(raw_record)
                   raw_record = []
                   raw_record.append(t)
           else:
               if t != "":
                   raw_record.append(t)
       else:
           pass
   # make sure we nab our last record and append it
   raw_records.append(raw_record)
   
   # print("Parsed %s records" % record_count)
   
   return raw_records
   
def process_raw_NTDSXtract_dump(filename):
   raw_dump = open(filename, 'r')
   raw_lines = []

   for line in raw_dump:
       raw_lines.append(line)

   raw_records = split_record_lines(raw_lines)
   parsed_accounts = []

   for raw_record in raw_records:
       t = parse_account(raw_record)
       parsed_accounts.append(t)
   return parsed_accounts


def print_hashtype_stats(accounts):
   lm_count = 0
   lm_hist_no_current = 0
   only_ntlm = 0

   for t in accounts:
       if t['ntlm_hash'] != None:
           if t['lm_hash'] == None:
               if t['lm_history'] == []:
                   only_ntlm +=1
       if t['lm_hash'] != None:
           lm_count += 1
       else:
           if t['lm_history'] != []:
               lm_hist_no_current += 1
   
   print("Accounts total: %s" % len(accounts))
   print("Accounts with LM Hashes: %s" % lm_count)
   print("Accounts with LM history and no LM current LM hashes: %s" % lm_hist_no_current)
   print("Accounts with only NTLM hashes: %s" % only_ntlm)
   return

def save_lm_hashes(accounts, filename, include_user=False):
   f = open(filename, "w")
   for account in accounts:
       if account['lm_hash'] != None:
           if include_user == False:
               f.write("%s\n" % account['lm_hash'])
           else:
               f.write("%s\n" % (account['sam_account_name'], account['lm_hash']) )
   f.close()
   
def save_ntlm_hashes(accounts, filename, include_user=False):
   f = open(filename, "w")
   for account in accounts:
       if account['ntlm_hash'] != None:
           if include_user == False:
               f.write("%s\n" % account['ntlm_hash'])
           else:
               f.write("%s\n" % (account['sam_account_name'], account['ntlm_hash']) )
   f.close()

def match_LM_cracked(accounts, cracked_file):
   #expects cracked_file in format of hash:plain
   # where hash is 32 character LM hash
   cracked = {}
   c = open(cracked_file, "r")
   for line in c:
       line = line.strip()
       full_hash = line[:32]
       password = line[33:] #skip the colon
       cracked[full_hash] = password
   matched = 0
   for i in range(0, len(accounts)):
       account_hash = accounts[i]['lm_hash']
       if account_hash != None:
           if account_hash in cracked:
               matched += 1
               accounts[i]['lm_plain'] = cracked[account_hash]
               #print("%s %s" % (accounts[i]['sam_account_name'],accounts[i]['lm_plain']))
   #print(matched)
   return accounts

def match_NTLM_cracked(accounts, cracked_file):
   #expects cracked_file in format of hash:plain
   # where hash is 32 character NTLM hash
   cracked = {}
   c = open(cracked_file, "r")
   for line in c:
       line = line.strip()
       full_hash = line[:32]
       password = line[33:] #skip the colon
       cracked[full_hash] = password
   matched = 0
   for i in range(0, len(accounts)):
       account_hash = accounts[i]['ntlm_hash']
       if account_hash != None:
           if account_hash in cracked:
               matched += 1
               accounts[i]['ntlm_plain'] = cracked[account_hash]
               #print("%s %s" % (accounts[i]['sam_account_name'],accounts[i]['ntlm_plain']))
   #print(matched)
   return accounts


parsed_accounts = process_raw_NTDSXtract_dump(NTDS_rawdog)
#print_hashtype_stats(parsed_accounts)
#save_lm_hashes(parsed_accounts,"LM_hashes.txt")
#save_ntlm_hashes(parsed_accounts,"NTLM_hashes.txt")
parsed_accounts = match_LM_cracked(parsed_accounts, LM_plus_plain)
parsed_accounts = match_NTLM_cracked(parsed_accounts, NTLM_plus_plain)


final_list = []
print_hashtype_stats(parsed_accounts)


for account in parsed_accounts:
   if account['ntlm_plain'] != None:
       final_list.append( [account['sam_account_name'], account['ntlm_plain']] )


print("Final cracked count: %s" % len(final_list))

final_crack_file = open(USER_PASS, "w")

for item in final_list:
   final_crack_file.write("%s\n" % ' '.join(item))

final_crack_file.close()

final_pass_file = open(PASSES, "w")

for item in final_list:
   final_pass_file.write("%s\n" % item[1])

final_pass_file.close()

"""
NTLM_histories = []
LM_histories = []



for account in parsed_accounts:
   
   if account['lm_history'] != []:

       lm_history = account['lm_history']
       for item in lm_history:
           LM_histories.append(item)

lmhisthashfile = open("LM_hist_hashes.txt","w")            
for history in LM_histories:
   lmhisthashfile.write("%s\n" % history[1])
lmhisthashfile.close()

"""
