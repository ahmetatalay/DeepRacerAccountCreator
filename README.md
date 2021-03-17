# Virtual DeepRacer League Child Account Creator

### Steps

#### 0. PreRequisites:
* Install the `Python 3.6+`
* Make sure that `Pip3` installed with `Python 3.6+`


#### 1. Set the Environment Variables:
`OU_NAME`: will be the Organization Name. Set whatever you want to use in this event.

`BUDGET_LIMIT`: will be the limit for child accounts. Such as, if you type 100, it will create $80 budget limit in child account, and alert notifiers list when it exceeds %80 percent of Budget limit

`DEFAULT_CHILD_ACCOUNT_PASS`: Set the default passwords for IAM users which will be created in Child accounts.

`BUDGET_NOTIFIERS_LIST`: It will be list of email addresses with comma seperated.(i.e. "test@gmail.com,test2@gmail.com"). Once the Budget limit exceeds %80 percent, it will notify the mail addresses entered in this list.


```
export AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID>
export AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY>
export AWS_DEFAULT_REGION=us-east-1

export OU_NAME="DeepRacerLeague"
export DEFAULT_CHILD_ACCOUNT_PASS=<DEFAULT PASSWORD>
export BUDGET_LIMIT=100
export BUDGET_NOTIFIERS_LIST="test@gmail.com,test2@gmail.com"
```

#### 2. Install the Python requirements
```
python3 -m venv virtualenv
source virtualenv/bin/activate

pip3 install -r requirements.txt
```

#### 3. Populate the input file with email addresses
For instance create `emails.csv` file, and type the email addresses with line by line. These will be used for creating child account. All Child account names will be started with these email addresses.
```
bash$ cat emails.csv
test+1@gmail.com
test+2@gmail.com
test+3@gmail.com
```

#### 4. Some Useful commands
* Run the help command to list available options: `python3 deepracer.py --help`
```
usage: deepracer.py [<args>]

AWS DeepRacer Account Bootstrap Script

optional arguments:
  -h, --help            show this help message and exit
  -i <Input-File-Name>, --input <Input-File-Name>
                        Enter the input file name(i.e. emails.csv)
  -m MODE, --mode MODE  Type the action you want to run. Available modes: <bootstrap, update-policies, attach-policies, detach-policies, update-budgets, delete-budgets>
```

* Bootstrap mode: `python3 deepracer.py --mode bootstrap --input emails.csv`
  * Create Child account listed in emails.csv
  * Create IAM user in each Child account
  * Set the necessary policies for IAM user
  * Create Budget limit for Child account
  * Move Child account to Organization Unit(i.e. DeepRacerLeague)

* Update Policies: `python3 deepracer.py --mode update-policies --input emails.csv`
  * Update the policies for Iam user in all Child accounts 

* Detach Policies: `python3 deepracer.py --mode detach-policies --input emails.csv`
  * Detach the policies for Iam user in all Child accounts

#### 5. Output Credential file
When the script executed with `bootstrap` mode, it will create `credentials.csv` file as an output which lists the IAM user name, Password, and account id. 
