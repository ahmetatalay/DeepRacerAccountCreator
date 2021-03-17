
import boto3
import pprint
import time
import ast
import random
import os
import json
import botocore 
import argparse
import sys
from botocore.exceptions import ClientError

def check_env_variables():
    if os.environ.get('OU_NAME') is not None:
        print("OU_NAME: {} is set as an environment variable.".format(os.environ.get('OU_NAME')))
    else:
        print('OU_NAME is NOT set as an environment variable. Exit!')
        exit(1)

    if os.environ.get('DEFAULT_CHILD_ACCOUNT_PASS') is not None:
        print("<DEFAULT_CHILD_ACCOUNT_PASS> is set as an environment variable.")
    else:
        print('<DEFAULT_CHILD_ACCOUNT_PASS> is NOT set as an environment variable. Exit!')
        exit(1)

    if os.environ.get('BUDGET_LIMIT') is not None:
        print("<BUDGET_LIMIT>: ${} is set as an environment variable.".format(os.environ.get('BUDGET_LIMIT')))
    else:
        print('<BUDGET_LIMIT> is NOT set as an environment variable. Exit!')
        exit(1)

    if os.environ.get('BUDGET_NOTIFIERS_LIST') is not None:
        print("<BUDGET_NOTIFIERS_LIST>: {} is set as an environment variable.".format(os.environ.get('BUDGET_NOTIFIERS_LIST')))
    else:
        print("<BUDGET_NOTIFIERS_LIST> is NOT set as an environment variable. It can be as a list as comma seperated.(i.e. BUDGET_NOTIFIERS_LIST='test@gmail.com, test2@gmail.com' ).Exit!")
        exit(1)

def get_account_id(client, email):
    paginator = client.get_paginator(
        'list_accounts').paginate().build_full_result()
    accounts = paginator['Accounts']

    account_id= None
    found = False
    for account in accounts:
        if str(email) == str(account['Email']):
            found = True
            account_id = account['Id']
            print("Child account email found {} with {}".format(email,account_id))
            break

    if not found:
        print("Child account email NOT exists:", email)

    return account_id

def create_child_account(client, email, account_name, role_name, iam_user_access_to_billing):
    response = client.create_account(
        Email=email,
        AccountName=account_name,
        RoleName=role_name,
        IamUserAccessToBilling=iam_user_access_to_billing
    )
    return response

def assume_child_credentials(client,account_id):
    role_arn="arn:aws:iam::{}:role/OrganizationAccountAccessRole".format(account_id)
    sesion_name="AssumeRoleSession-{}".format(random.randint(0,10000000000000000)+1)

    result= None
    while True:
        try:
            result = client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=sesion_name,
                DurationSeconds=3600
            )
            if result is None:
               raise botocore.exceptions.ClientError
        except botocore.exceptions.ClientError as err:
            time.sleep(5)
            response = err.response
            if (response and response.get("Error", {}).get("Code") == "AccessDenied"):
                print("Failed to assume role. Error:{}.It will try to assume role again!".format(err.response['Error']['Code']))
                continue
        break
    
    return result['Credentials']

def exists_iam_user(iam_client,account_name):
    paginator = iam_client.get_paginator(
        'list_users').paginate().build_full_result()

    users = paginator['Users']

    iam_user_found = False;
    for user in users:
        if str(account_name) == str(user['UserName']): 
            iam_user_found= True
            break

    return iam_user_found

def exists_attendee_policy(iam_client,policy_name):
    paginator = iam_client.get_paginator(
        'list_policies').paginate().build_full_result()

    policies = paginator['Policies']

    iam_policy_found = False;
    for policy in policies:
        if str(policy_name) == str(policy['Name']): 
            iam_policy_found= True
            break

    return iam_policy_found

def create_custom_iam_userpolicy(iam_client):
    policy_name = "DeepRacerWorkshopAttendeePolicy"
    policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:ChangePassword"
                ],
                "Resource": "*"
            }
        ]
    })

    create_policy_response=iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=policy_document
    )

    return create_policy_response['Policy']['Arn']

def attach_iam_user_policies(iam_client,account_name,custom_policy_arn):
    iam_client.attach_user_policy(UserName=account_name,PolicyArn=custom_policy_arn)
    iam_client.attach_user_policy(UserName=account_name,PolicyArn="arn:aws:iam::aws:policy/AWSDeepRacerFullAccess")
    iam_client.attach_user_policy(UserName=account_name,PolicyArn="arn:aws:iam::aws:policy/AWSDeepRacerRoboMakerAccessPolicy")
    iam_client.attach_user_policy(UserName=account_name,PolicyArn="arn:aws:iam::aws:policy/service-role/AWSDeepRacerServiceRolePolicy")

def update_policies(account_id,iam_user_name,iam_client):
    try:
        iam_client.detach_user_policy(UserName=iam_user_name,
            PolicyArn="arn:aws:iam::{}:policy/DeepRacerWorkshopAttendeePolicy".format(account_id)
        )
        print("Detached DeepRacerWorkshopAttendeePolicy from IAM User: {} in account id:{}".format(iam_user_name,account_id))

        iam_client.delete_policy(PolicyArn="arn:aws:iam::{}:policy/DeepRacerWorkshopAttendeePolicy".format(account_id))
        print("Deleted DeepRacerWorkshopAttendeePolicy in account id:{}".format(account_id))
    except iam_client.exceptions.NoSuchEntityException as error:
        print("Policy already detached --> Message: {}".format(error))

    custom_policy_arn=create_custom_iam_userpolicy(iam_client)
    print("Created DeepRacerWorkshopAttendeePolicy in account id:{}".format(account_id))
    iam_client.attach_user_policy(UserName=iam_user_name,PolicyArn=custom_policy_arn)
    print("Attached DeepRacerWorkshopAttendeePolicy to IAM User:{} in account id:{}".format(iam_user_name, account_id))

def set_permissions(sts_client,account_name,account_id,default_password,type=None):
    assume_creds = assume_child_credentials(sts_client,account_id)

    iam_client = boto3.client('iam', region_name=os.environ['AWS_DEFAULT_REGION'] ,
                        aws_access_key_id=assume_creds['AccessKeyId'],
                        aws_secret_access_key=assume_creds['SecretAccessKey'],
                        aws_session_token = assume_creds['SessionToken'])
    iam_user_name="{}-deepracer-{}".format(account_name,account_id)

    if type == "update" and not exists_iam_user(iam_client,iam_user_name):
        print("IAM user:{} not found, NO need to update. You should first bootstrap it. Exit!".format(iam_user_name))
        return

    if type == "update" and exists_iam_user(iam_client,iam_user_name):
        print("IAM user:{} found, It will update the policies!".format(iam_user_name))
        update_policies(account_id,iam_user_name,iam_client)
        return

    if type == "attach" and not exists_iam_user(iam_client,iam_user_name):
        print("IAM user:{} not found, NO need to attach. You should first bootstrap it. Exit!".format(iam_user_name))
        return

    if type == "attach" and exists_iam_user(iam_client,iam_user_name):
        print("IAM user:{} found, It will attach the policies!".format(iam_user_name))
        iam_client.attach_user_policy(UserName=iam_user_name,
            PolicyArn="arn:aws:iam::{}:policy/DeepRacerWorkshopAttendeePolicy".format(account_id)
        )
        print("Attached DeepRacerWorkshopAttendeePolicy from IAM User: {} in account id:{}".format(iam_user_name,account_id))

        iam_client.attach_user_policy(UserName=iam_user_name,PolicyArn="arn:aws:iam::aws:policy/AWSDeepRacerFullAccess")
        print("Attached AWSDeepRacerFullAccess from IAM User: {} in account id:{}".format(iam_user_name,account_id))

        iam_client.attach_user_policy(UserName=iam_user_name,PolicyArn="arn:aws:iam::aws:policy/AWSDeepRacerRoboMakerAccessPolicy")
        print("Attached AWSDeepRacerRoboMakerAccessPolicy from IAM User: {} in account id:{}".format(iam_user_name,account_id))

        iam_client.attach_user_policy(UserName=iam_user_name,PolicyArn="arn:aws:iam::aws:policy/service-role/AWSDeepRacerServiceRolePolicy")
        print("Attached AWSDeepRacerServiceRolePolicy from IAM User: {} in account id:{}".format(iam_user_name,account_id))
        return

    if type == "detach" and not exists_iam_user(iam_client,iam_user_name):
        print("IAM user:{} not found, NO need to detach. You should first bootstrap it. Exit!".format(iam_user_name))
        return

    if type == "detach" and exists_iam_user(iam_client,iam_user_name):
        try:
            print("IAM user:{} found, It will detach the policies!".format(iam_user_name))
            iam_client.detach_user_policy(UserName=iam_user_name,
                PolicyArn="arn:aws:iam::{}:policy/DeepRacerWorkshopAttendeePolicy".format(account_id)
            )
            print("Detached DeepRacerWorkshopAttendeePolicy from IAM User: {} in account id:{}".format(iam_user_name,account_id))

            iam_client.detach_user_policy(UserName=iam_user_name,PolicyArn="arn:aws:iam::aws:policy/AWSDeepRacerFullAccess")
            print("Detached AWSDeepRacerFullAccess from IAM User: {} in account id:{}".format(iam_user_name,account_id))

            iam_client.detach_user_policy(UserName=iam_user_name,PolicyArn="arn:aws:iam::aws:policy/AWSDeepRacerRoboMakerAccessPolicy")
            print("Detached AWSDeepRacerRoboMakerAccessPolicy from IAM User: {} in account id:{}".format(iam_user_name,account_id))

            iam_client.detach_user_policy(UserName=iam_user_name,PolicyArn="arn:aws:iam::aws:policy/service-role/AWSDeepRacerServiceRolePolicy")
            print("Detached AWSDeepRacerServiceRolePolicy from IAM User: {} in account id:{}".format(iam_user_name,account_id))
        except iam_client.exceptions.NoSuchEntityException as error:
            print("Policy already detached --> Message: {}".format(error))

        return


    if not exists_iam_user(iam_client,iam_user_name):
        iam_client.create_user(UserName=iam_user_name)
        print("Created IAM User:{} in account id:{}".format(iam_user_name,account_id))
        custom_policy_arn=create_custom_iam_userpolicy(iam_client)
        print("Created DeepRacerWorkshopAttendeePolicy in account id:{}".format(account_id))
        attach_iam_user_policies(iam_client,iam_user_name,custom_policy_arn)
        print("Attached DeepRacerWorkshopAttendeePolicy to IAM User:{} in account id:{}".format(iam_user_name, account_id))
        iam_client.create_login_profile(UserName=iam_user_name,Password=default_password,
                PasswordResetRequired=True
        )
        print("Created Login Profile for IAM user: {} in account id:{}".format(iam_user_name,account_id))
    else:
        update_policies(account_id,iam_user_name,iam_client)

    credentialsOperations(account_id,iam_user_name,account_name,default_password)

def credentialsOperations(account_id,iam_user_name,account_name,default_password):
    existsCred = False
    with open('credentials.csv') as read_file:
        datafile = read_file.readlines()
        for line in datafile:
            if account_id in line:
                existsCred = True 
                break
    
    write_file = open("credentials.csv", "a")
    if not existsCred:
        write_file.write("{account_name};https://{account_id}.signin.aws.amazon.com/console;{iam_user_name};{default_password}\n".format(iam_user_name=iam_user_name,account_name=account_name,account_id=account_id,default_password=default_password))
        print("Account id: {} credential written to credentials.csv".format(account_id))
    else:
        print("Account id: {} credential already exists in credentials.csv".format(account_id))

def create_org_unit(organization_client,source_root_id,ou_name):
    paginator = organization_client.get_paginator(
        'list_organizational_units_for_parent').paginate(ParentId=source_root_id).build_full_result()

    ous = paginator['OrganizationalUnits']

    ou_found = False;
    org_unit = None
    for ou in ous:
        if str(ou_name) == str(ou['Name']): 
            ou_found= True
            org_unit = ou
            break

    if not ou_found:
        response = organization_client.create_organizational_unit(
            ParentId=source_root_id,
            Name=ou_name,
        )
        print("Organization Unit:{} is created under Root id:{}".format(ou_name,source_root_id))    
        return response['OrganizationalUnit']
    else:
        print("Organization Unit:{} is Already exists under Root id:{}".format(ou_name,source_root_id))  

    return org_unit

def move_child_accounts_to_org_unit(organization_client,account_id,source_root_id,dest_ou_id,account_name):
    paginator = organization_client.get_paginator(
        'list_accounts_for_parent').paginate(ParentId=dest_ou_id).build_full_result()

    child_accounts = paginator['Accounts']

    is_moved = False;

    for child_account in child_accounts:
        if str(account_name) == str(child_account['Name']): 
            is_moved= True
            break

    if not is_moved:
        organization_client.move_account(
            AccountId=account_id,
            SourceParentId=source_root_id,
            DestinationParentId=dest_ou_id
        )
        print("Child Account:{} is  moved to organization unit:{}".format(account_id,dest_ou_id))    
    else:
        print("Child Account:{}  is Already in organization unit:{}".format(account_id,dest_ou_id))         

def set_budget_alert_for_child(sts_client,account_id,amount,budget_name,budget_notifier_list, type=None ):
    print("Setting Budget Alert for child account:{}".format(budget_name))
    assume_creds = assume_child_credentials(sts_client,account_id)

    budgets_client = boto3.client('budgets', region_name=os.environ['AWS_DEFAULT_REGION'] ,
                        aws_access_key_id=assume_creds['AccessKeyId'],
                        aws_secret_access_key=assume_creds['SecretAccessKey'],
                        aws_session_token = assume_creds['SessionToken'])

    budget_found= False

    count = 0
    while True:
        if count >= 30:
            break
        try:
            budgets = budgets_client.describe_budgets(AccountId=account_id)['Budgets']
            for budget in budgets:
                if budget['BudgetName'] == budget_name:
                    print("Budget: {} is already exists.".format(budget_name))
                    budget_found = True
                    break
        except KeyError:
            budget_found = False
        except ClientError as e:
            time.sleep(5)
            count = count+1
            if e.response['Error']['Code'] == 'SubscriptionRequiredException':
                print("Trial:{} Failed to call Budget API. It will try again!".format(count,e.response['Error']['Code']))
                continue
        break 

    if type == "delete" and budget_found:
        print("Budget: {} is exists. It will delete the budget".format(budget_name))
        budgets_client.delete_budget(AccountId=account_id,BudgetName=budget_name)
        return

    if type == "delete" and not budget_found:
        print("Budget: {} is NOT exists. No need to delete".format(budget_name))
        return

    if type == "update" and not budget_found:
        print("Budget: {} is NOT exists. No need to update".format(budget_name))
        return

    if type == "update" and budget_found:
        print("Budget: {} is exists. It will be deleted, then re-created".format(budget_name))
        budgets_client.delete_budget(AccountId=account_id,BudgetName=budget_name)
        budget_found = False

    if not budget_found:
        print("Budget limit: ${} for budget name:{} will be created".format(amount,budget_name))
        response = budgets_client.create_budget(
            AccountId=account_id,
            Budget={
                'BudgetName': budget_name,
                'BudgetLimit': {
                    'Amount': str(amount),
                    'Unit': 'USD'
                },
                'CostTypes': {
                    'IncludeTax': True,
                    'IncludeSubscription': True,
                    'UseBlended': False,
                    'IncludeRefund': True,
                    'IncludeCredit': True,
                    'IncludeUpfront': True,
                    'IncludeRecurring': True,
                    'IncludeOtherSubscription': True,
                    'IncludeSupport': True,
                    'IncludeDiscount': True,
                    'UseAmortized': True
                },
                'TimeUnit': 'MONTHLY',
                'BudgetType': 'COST'
            },
            NotificationsWithSubscribers=[
                {
                    'Notification': {
                        'NotificationType': 'ACTUAL',
                        'ComparisonOperator': 'GREATER_THAN',
                        'Threshold': 80,
                        'ThresholdType': 'PERCENTAGE'
                    },
                    'Subscribers': budget_notifier_list
                },
            ]
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print("Budget:{} is created under account id: {}".format(budget_name,account_id))

def get_root_id(organization_client):
    return organization_client.list_roots()['Roots'][0]['Id']

def parse_args():
    parser = argparse.ArgumentParser(description='AWS DeepRacer Account Bootstrap Script', usage='deepracer.py [<args>]')
    parser.add_argument(
    '-i',
    '--input',
    metavar="<Input-File-Name>",
    nargs=1,
    help='Enter the input file name(i.e. emails.csv)',required=True)

    parser.add_argument(
    '-m',
    '--mode',
    nargs=1,
    help='Type the action you want to run.  Available modes: <bootstrap, update-policies, attach-policies, detach-policies, update-budgets, delete-budgets>  ',required=True)

    args = parser.parse_args(sys.argv[1:])
    return vars(args)

def bootstrap(account_id,account_name,email,source_root_id,dest_ou_id,organization_client,sts_client,default_password,amount,budget_notifier_list):
    if not account_id:
        print("Creating child account: {} under root account".format(account_name))
        create_account_response = organization_client.create_account(
            Email=email,
            AccountName=account_name,
            RoleName="OrganizationAccountAccessRole",
            IamUserAccessToBilling="DENY"
        )
        
        count =0
        while True:
            describe_account_response = organization_client.describe_create_account_status(
                CreateAccountRequestId=create_account_response['CreateAccountStatus']['Id']
            )
            if describe_account_response['CreateAccountStatus']['State'] == "SUCCEEDED":
                print("Child Account: {} is created under root account".format(account_name))
                break
            time.sleep(3)
            count = count +1
            if describe_account_response['CreateAccountStatus']['State'] == "FAILED" or count > 20: # 20x3= 60 sec timeout
                raise Exception("Problem occurred while creating account id")
                exit()

        child_account_id = get_account_id(organization_client,email)  
        set_permissions(sts_client,account_name,child_account_id,default_password)

        budget_name="Budget-Alert-for-{}-{}".format(account_name,child_account_id)
        set_budget_alert_for_child(sts_client,child_account_id,amount,budget_name,budget_notifier_list)

        move_child_accounts_to_org_unit(organization_client,child_account_id,source_root_id,dest_ou_id,account_name)
    else:
        print("Updating permissions for existing child account: {}".format(account_name))
        set_permissions(sts_client,account_name,account_id,default_password)
        
        budget_name="Budget-Alert-for-{}-{}".format(account_name,account_id)
        set_budget_alert_for_child(sts_client,account_id,amount,budget_name,budget_notifier_list)

        move_child_accounts_to_org_unit(organization_client,account_id,source_root_id,dest_ou_id,account_name)

def run_mode(mode,email,budget_notifier_list,source_root_id,dest_ou_id,organization_client,sts_client):
    print("------")
    account_name = email.split('@')[0]
    account_id = get_account_id(organization_client, email)
    default_password=os.environ.get('DEFAULT_CHILD_ACCOUNT_PASS')
    amount = os.environ.get('BUDGET_LIMIT')    

    if mode == "bootstrap":
        bootstrap(account_id,account_name,email,source_root_id,dest_ou_id,organization_client,sts_client,default_password,amount,budget_notifier_list)
    elif mode == "update-policies":
        set_permissions(sts_client,account_name,account_id,default_password,type="update")
    elif mode == "detach-policies":
        set_permissions(sts_client,account_name,account_id,default_password,type="detach")
    elif mode == "attach-policies":
        set_permissions(sts_client,account_name,account_id,default_password,type="attach")
    elif mode == "update-budgets":
        budget_name="Budget-Alert-for-{}-{}".format(account_name,account_id)
        set_budget_alert_for_child(sts_client,account_id,amount,budget_name,budget_notifier_list,type="update")
    elif mode == "delete-budgets":
        budget_name="Budget-Alert-for-{}-{}".format(account_name,account_id)
        set_budget_alert_for_child(sts_client,account_id,amount,budget_name,budget_notifier_list, type="delete")
    else:
        print("No available modes found. Please enter Available modes: <bootstrap, update-policies, attach-policies, detach-policies, update-budgets, delete-budgets>")
        exit(1)

if __name__ == '__main__':
    args = parse_args()
    mode = args.get('mode')[0]
    file_name = args.get('input')[0]
    check_env_variables()

    organization_client = boto3.client('organizations')
    sts_client = boto3.client('sts')

    budget_notifier_list = [notifier.replace(" ","") for notifier in os.environ.get("BUDGET_NOTIFIERS_LIST").split(',')] 
    budget_notifier_list = [{'SubscriptionType': 'EMAIL','Address': notifier } for notifier in budget_notifier_list] 

    if len(budget_notifier_list) > 10:
        print("Maximum 10 emails are supported for budget notifier in 'BUDGET_NOTIFIERS_LIST' environment variable.")
        exit(1)

    ou_name = os.environ.get('OU_NAME')
    source_root_id = get_root_id(organization_client)
    dest_ou_id= create_org_unit(organization_client,source_root_id,ou_name)['Id']
    print("Source root id:'{}', Dest OU ID: '{}' \n".format(source_root_id,dest_ou_id))

    emailfile = open(file_name, 'r')
    emaillist = [l for l in (line.strip() for line in emailfile) if l]

    for email in emaillist:
        run_mode(mode,email,budget_notifier_list,source_root_id,dest_ou_id,organization_client,sts_client)

