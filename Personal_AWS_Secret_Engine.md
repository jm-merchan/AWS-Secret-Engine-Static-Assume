```python
# Read aws credentials from csv file and set as environment variables for Vault configuration
import csv, os
with open('vault_test_accessKeys.csv', 'r', encoding='utf-8-sig') as csvfile:
    reader = csv.DictReader(csvfile)
    creds = next(reader)
    access_key = creds['Access key ID']
    secret_key = creds['Secret access key']
    os.environ['AWS_ACCESS_KEY_ID'] = access_key
    os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
    print(f"Access Key: {access_key[:8]}...")
    print(f"Credentials loaded.")
```

    Access Key: AKIATGPH...
    Credentials loaded.


# AWS Secret Engine


```python
! open -a Podman\ Desktop
```


```python
%env VAULT_ADDR=http://127.0.0.1:8200
%env VAULT_TOKEN=root
%env VAULT_KMIP_PORT=5696
%env VAULT_PORT=8200
%env REGION=eu-west-3
```

    env: VAULT_ADDR=http://127.0.0.1:8200
    env: VAULT_TOKEN=root
    env: VAULT_KMIP_PORT=5696
    env: VAULT_PORT=8200
    env: REGION=eu-west-3


### Create a Vault Server in Podman


```bash
%%bash
# Change the path to your license file

export VAULT_LICENSE=$(cat vault.hclic)

# Refresh Vault docker image with latest version
podman pull hashicorp/vault-enterprise

podman run -d --rm --name vault-enterprise --cap-add=IPC_LOCK \
  -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_TOKEN}" \
  -e "VAULT_DEV_LISTEN_ADDRESS=:${VAULT_PORT}" \
  -e "VAULT_LICENSE=${VAULT_LICENSE}" \
  -p ${VAULT_KMIP_PORT}:${VAULT_KMIP_PORT} \
  -p 8200:${VAULT_PORT} \
  hashicorp/vault-enterprise:latest
```

    Trying to pull docker.io/hashicorp/vault-enterprise:latest...
    Getting image source signatures
    Copying blob sha256:3856d5e105abeb06e9371ce18428da65c810eec9c104a69385558d418dad3721
    Copying blob sha256:9268c2c682e14c33908ef70b5501cf78da853737da5beb3e693997fb6fafe7c2
    Copying blob sha256:606106f6ce6e21a4370cb6e512d9dea437a224d101a417c66bd57187c0dcb10f
    Copying blob sha256:9f135f2d2e021dcb6262233a0d8c2ab29f0330c55669049ef10c707bf79fc898
    Copying blob sha256:5123808017adc4dc844c63f2f6a4973a2d9213ef63bf99e4bbce7aa16ac4efc1
    Copying blob sha256:3fe223cae42bedc55ce142cc6854575d254daf333cd2f0faaf5e1a8c0fe9feaf
    Copying blob sha256:0d0e4560c730c269565d0616197a73116fc3ff78669947189f2cf716b6a3fde0
    Copying config sha256:f701c8517313363055d0a3c39a113e427f5d52009c233847c9a0545cd32b7686
    Writing manifest to image destination


    f701c8517313363055d0a3c39a113e427f5d52009c233847c9a0545cd32b7686
    a061947008a58ecd05746349002c8b330486936ecb6ac16a76ae518fb4113ec8


### Check if Vault is running


```python
! podman ps
```

    CONTAINER ID  IMAGE                                        COMMAND      CREATED                 STATUS                            PORTS                                           NAMES
    a061947008a5  docker.io/hashicorp/vault-enterprise:latest  server -dev  Less than a second ago  Up Less than a second (starting)  0.0.0.0:5696->5696/tcp, 0.0.0.0:8200->8200/tcp  vault-enterprise


## Enable the AWS secrets engine


```python
! vault secrets enable aws
```

    [0mSuccess! Enabled the aws secrets engine at: aws/[0m

! vault secrets enable -output-curl-string aws 
### Create `vault-root` IAM User
Vault's `aws/config/root` credentials need broad IAM permissions to manage dynamic users, rotate keys, etc.  
We create a dedicated `vault-root` IAM user with the [IAM permissions policy recommended by Vault](https://developer.hashicorp.com/vault/docs/secrets/aws#iam-permissions-policy-for-vault).


```bash
%%bash
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
IAM_USER="vault-root"

echo "Account ID: $ACCOUNT_ID"
echo "User:       $IAM_USER"

# Create IAM user (skip if already exists)
if aws iam get-user --user-name "$IAM_USER" &>/dev/null; then
    echo "IAM user $IAM_USER already exists, skipping creation."
else
    aws iam create-user --user-name "$IAM_USER"
    echo "IAM user created."
fi

# Create the Vault IAM permissions policy (from Vault docs)
# Adding permissions for app-test user as well to allow testing with both vault-root and app-test users
POLICY_NAME="VaultIAMPolicy"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

cat > /tmp/vault-iam-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
        "iam:CreateUser",
        "iam:DeleteAccessKey",
        "iam:DeleteUser",
        "iam:DeleteUserPolicy",
        "iam:DetachUserPolicy",
        "iam:GetUser",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListUserPolicies",
        "iam:PutUserPolicy",
        "iam:AddUserToGroup",
        "iam:RemoveUserFromGroup",
        "iam:TagUser"
      ],
      "Resource": [
        "arn:aws:iam::${ACCOUNT_ID}:user/vault-*",
        "arn:aws:iam::${ACCOUNT_ID}:user/app-test"
      ]
    }
  ]
}
EOF

# Create or update the IAM policy
if aws iam get-policy --policy-arn "$POLICY_ARN" &>/dev/null; then
    echo "Policy $POLICY_NAME already exists, creating new version..."
    # Delete oldest non-default version if there are 5 versions (AWS limit)
    OLD_VERSION=$(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
        --query 'Versions[?IsDefaultVersion==`false`]|[-1].VersionId' --output text)
    if [ "$OLD_VERSION" != "None" ] && [ -n "$OLD_VERSION" ]; then
        aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$OLD_VERSION" 2>/dev/null || true
    fi
    aws iam create-policy-version --policy-arn "$POLICY_ARN" \
        --policy-document file:///tmp/vault-iam-policy.json --set-as-default
else
    aws iam create-policy --policy-name "$POLICY_NAME" \
        --policy-document file:///tmp/vault-iam-policy.json
fi

# Attach the policy to vault-root user
aws iam attach-user-policy --user-name "$IAM_USER" --policy-arn "$POLICY_ARN"
echo "Policy $POLICY_NAME attached to $IAM_USER."

# Delete all existing access keys (AWS limit is 2)
echo ""
echo "Cleaning up old access keys..."
for old_key in $(aws iam list-access-keys --user-name "$IAM_USER" --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
    echo "  Deleting key: $old_key"
    aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$old_key"
done

# Create a new access key
echo ""
echo "Creating new access key..."
aws iam create-access-key --user-name "$IAM_USER" \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' \
    --output text | while read key secret; do
    echo "VAULT_IAM_ACCESS_KEY=$key"
    echo "VAULT_IAM_SECRET_KEY=$secret"
done
```

    Account ID: 220065406052
    User:       vault-root
    {
        "User": {
            "Path": "/",
            "UserName": "vault-root",
            "UserId": "AIDATGPHLTRSLIUFTJO2Q",
            "Arn": "arn:aws:iam::220065406052:user/vault-root",
            "CreateDate": "2026-02-18T15:33:31+00:00"
        }
    }
    IAM user created.
    {
        "Policy": {
            "PolicyName": "VaultIAMPolicy",
            "PolicyId": "ANPATGPHLTRSOKMFOMLLV",
            "Arn": "arn:aws:iam::220065406052:policy/VaultIAMPolicy",
            "Path": "/",
            "DefaultVersionId": "v1",
            "AttachmentCount": 0,
            "PermissionsBoundaryUsageCount": 0,
            "IsAttachable": true,
            "CreateDate": "2026-02-18T15:33:33+00:00",
            "UpdateDate": "2026-02-18T15:33:33+00:00"
        }
    }
    Policy VaultIAMPolicy attached to vault-root.
    
    Cleaning up old access keys...
    
    Creating new access key...
    VAULT_IAM_ACCESS_KEY=AKIATGPHLTRSORPYLFUG
    VAULT_IAM_SECRET_KEY=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


### Set `vault-root` Credentials
Copy the `VAULT_IAM_ACCESS_KEY` and `VAULT_IAM_SECRET_KEY` values from the output above.


```python
%env VAULT_IAM_ACCESS_KEY=AKIATGPHLTRSORPYLFUG
%env VAULT_IAM_SECRET_KEY=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
```

    env: VAULT_IAM_ACCESS_KEY=AKIATGPHLTRSORPYLFUG
    env: VAULT_IAM_SECRET_KEY=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



```bash
%%bash
# Configure Vault AWS secrets engine with static IAM user credentials
vault write aws/config/root \
    access_key=$VAULT_IAM_ACCESS_KEY \
    secret_key=$VAULT_IAM_SECRET_KEY \
    region=$REGION
```

    Success! Data written to: aws/config/root

%%bash
# Configure Vault AWS secrets engine with static IAM user credentials
vault write -output-curl-string aws/config/root \
    access_key=$VAULT_IAM_ACCESS_KEY \
    secret_key=$VAULT_IAM_SECRET_KEY \
    region=$REGION
## Rotate root credentials


```python
! vault write -f aws/config/rotate-root
```

    [0mKey           Value
    ---           -----
    access_key    AKIATGPHLTRSLWPMOMVS[0m


![image.png](Personal_AWS_Secret_Engine_files/image.png)
! vault write -f -output-curl-string aws/config/rotate-root
### Create `app-test` IAM User (for Static Role)
This user simulates an application's IAM identity. Vault will manage (rotate) its access keys via a [Static Role](https://developer.hashicorp.com/vault/docs/secrets/aws#static-roles).  
We give it a simple EC2 read-only policy so we can verify the credentials work.


```bash
%%bash
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
IAM_USER="app-test"

echo "Account ID: $ACCOUNT_ID"
echo "User:       $IAM_USER"

# Create IAM user (skip if already exists)
if aws iam get-user --user-name "$IAM_USER" &>/dev/null; then
    echo "IAM user $IAM_USER already exists, skipping creation."
else
    aws iam create-user --user-name "$IAM_USER"
    echo "IAM user created."
fi

# Create a simple EC2 read-only policy for the app
POLICY_NAME="AppTestEC2ReadOnly"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

cat > /tmp/app-test-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeInstances",
        "kms:ListKeys",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Create or update the IAM policy
if aws iam get-policy --policy-arn "$POLICY_ARN" &>/dev/null; then
    echo "Policy $POLICY_NAME already exists, creating new version..."
    OLD_VERSION=$(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
        --query 'Versions[?IsDefaultVersion==`false`]|[-1].VersionId' --output text)
    if [ "$OLD_VERSION" != "None" ] && [ -n "$OLD_VERSION" ]; then
        aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$OLD_VERSION" 2>/dev/null || true
    fi
    aws iam create-policy-version --policy-arn "$POLICY_ARN" \
        --policy-document file:///tmp/app-test-policy.json --set-as-default
else
    aws iam create-policy --policy-name "$POLICY_NAME" \
        --policy-document file:///tmp/app-test-policy.json
fi

# Attach the policy to app-test user
aws iam attach-user-policy --user-name "$IAM_USER" --policy-arn "$POLICY_ARN"
echo "Policy $POLICY_NAME attached to $IAM_USER."

# Delete all existing access keys (AWS limit is 2)
echo ""
echo "Cleaning up old access keys..."
for old_key in $(aws iam list-access-keys --user-name "$IAM_USER" --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
    echo "  Deleting key: $old_key"
    aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$old_key"
done

# Create a new access key (Vault static roles need an initial key to exist)
echo ""
echo "Creating initial access key for $IAM_USER..."
aws iam create-access-key --user-name "$IAM_USER" \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' \
    --output text | while read key secret; do
    echo "Initial Access Key: $key"
    echo "(Vault will rotate this key automatically)"
done
```

    Account ID: 220065406052
    User:       app-test
    {
        "User": {
            "Path": "/",
            "UserName": "app-test",
            "UserId": "AIDATGPHLTRSDSNLGOUUP",
            "Arn": "arn:aws:iam::220065406052:user/app-test",
            "CreateDate": "2026-02-18T15:36:10+00:00"
        }
    }
    IAM user created.
    {
        "Policy": {
            "PolicyName": "AppTestEC2ReadOnly",
            "PolicyId": "ANPATGPHLTRSGVUFXATDV",
            "Arn": "arn:aws:iam::220065406052:policy/AppTestEC2ReadOnly",
            "Path": "/",
            "DefaultVersionId": "v1",
            "AttachmentCount": 0,
            "PermissionsBoundaryUsageCount": 0,
            "IsAttachable": true,
            "CreateDate": "2026-02-18T15:36:12+00:00",
            "UpdateDate": "2026-02-18T15:36:12+00:00"
        }
    }
    Policy AppTestEC2ReadOnly attached to app-test.
    
    Cleaning up old access keys...
    
    Creating initial access key for app-test...
    Initial Access Key: AKIATGPHLTRSCRNOWHGM
    (Vault will rotate this key automatically)


### Configure Vault Static Role for `app-test`
A [static role](https://developer.hashicorp.com/vault/docs/secrets/aws#static-roles) is a 1-to-1 mapping of a Vault role to an IAM user.  
Vault stores the current access key and **automatically rotates** it on a configurable period (`rotation_period`).


```bash
%%bash
# Create static role: Vault will manage app-test's access keys
# rotation_period = how often Vault rotates the key (e.g. 1h for demo)
vault write aws/static-roles/app-test \
    username=app-test \
    rotation_period=1h

```

    Key                         Value
    ---                         -----
    assume_role_arn             n/a
    assume_role_session_name    n/a
    external_id                 n/a
    id                          AIDATGPHLTRSDSNLGOUUP
    name                        app-test
    rotation_period             1h
    username                    app-test


![image.png](Personal_AWS_Secret_Engine_files/image.png)
%%bash
vault write -output-curl-string aws/static-roles/app-test \
    username=app-test \
    rotation_period=1h
### Test    


```bash
%%bash
vault read aws/static-creds/app-test
```

    Key           Value
    ---           -----
    access_key    AKIATGPHLTRSOAVITYPE
    expiration    2026-02-18T16:36:43.627294144Z
    secret_key    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

%%bash
vault read -output-curl-string aws/static-creds/app-test
### Verification — Read Static Credentials
Read the current access key managed by Vault for `app-test`, then use it to call AWS APIs.


```bash
%%bash
# Read the static credentials that Vault manages for app-test
echo "=== Static Credentials ==="
vault read aws/static-creds/app-test

echo ""

# Use the static credentials to call AWS
CREDS=$(vault read -format=json aws/static-creds/app-test)
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.data.access_key')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.data.secret_key')
unset AWS_SESSION_TOKEN  # static creds don't use session tokens

sleep 10  # Wait for AWS IAM to propagate the new key (eventual consistency)

echo "=== Caller Identity (using app-test static creds) ==="
aws sts get-caller-identity

echo ""

echo "=== EC2 Describe Regions ==="
aws ec2 describe-regions --query 'Regions[*].RegionName' --output table --region $REGION

echo ""

echo "=== EC2 Describe Instances ==="
aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,State:State.Name,AZ:Placement.AvailabilityZone,Name:Tags[?Key==`Name`]|[0].Value}' \
    --output table --region $REGION

echo ""

echo "=== KMS List Keys ==="
aws kms list-keys --query 'Keys[*].KeyId' --output table --region $REGION

echo ""

# Note: Static role credentials rotate automatically based on rotation_period.
# There is no manual rotate endpoint for static roles.
# To see rotation details, read the static role config:
echo "=== Static Role Config (rotation_period) ==="
vault read aws/static-roles/app-test
```

    === Static Credentials ===
    Key           Value
    ---           -----
    access_key    AKIATGPHLTRSOAVITYPE
    expiration    2026-02-18T16:36:43.627294144Z
    secret_key    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
    
    === Caller Identity (using app-test static creds) ===
    {
        "UserId": "AIDATGPHLTRSDSNLGOUUP",
        "Account": "220065406052",
        "Arn": "arn:aws:iam::220065406052:user/app-test"
    }
    
    === EC2 Describe Regions ===
    --------------------
    |  DescribeRegions |
    +------------------+
    |  ap-south-1      |
    |  eu-north-1      |
    |  eu-west-3       |
    |  eu-west-2       |
    |  eu-south-2      |
    |  eu-west-1       |
    |  ap-northeast-3  |
    |  ap-northeast-2  |
    |  ap-northeast-1  |
    |  ca-central-1    |
    |  sa-east-1       |
    |  ap-southeast-1  |
    |  ap-southeast-2  |
    |  eu-central-1    |
    |  us-east-1       |
    |  us-east-2       |
    |  us-west-1       |
    |  us-west-2       |
    +------------------+
    
    === EC2 Describe Instances ===
    
    === KMS List Keys ===
    
    === Static Role Config (rotation_period) ===
    Key                         Value
    ---                         -----
    assume_role_arn             n/a
    assume_role_session_name    n/a
    external_id                 n/a
    id                          AIDATGPHLTRSDSNLGOUUP
    name                        app-test
    rotation_period             1h
    username                    app-test


## Assume Role

### Static Role via Assumed Role (Enterprise)
In this example we use a **separate** IAM user `vault-assumed` with its own Vault mount `aws-assumed`.  
Vault assumes an IAM role (`vault-assume`) which has permissions to manage the `test-assumed` user's credentials.  
This is the [cross-account static role management](https://developer.hashicorp.com/vault/docs/secrets/aws#cross-account-static-role-management) pattern — here demonstrated in a single account.

**Flow:** `vault-assumed` (config/root) → `sts:AssumeRole` → `vault-assume` (IAM Role) → manages `test-assumed` (IAM User)

### Step 1 — Create `vault-assumed` IAM User
This user will be the root credentials for the `aws-assumed` mount. It only needs `sts:AssumeRole` permission.

![image.png](Personal_AWS_Secret_Engine_files/image.png)

![image.png](Personal_AWS_Secret_Engine_files/image.png)


```bash
%%bash
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
IAM_USER="vault-assumed"

echo "Account ID: $ACCOUNT_ID"
echo "User:       $IAM_USER"

# Create IAM user (skip if already exists)
if aws iam get-user --user-name "$IAM_USER" &>/dev/null; then
    echo "IAM user $IAM_USER already exists, skipping creation."
else
    aws iam create-user --user-name "$IAM_USER"
    echo "IAM user created."
fi

# Policy: sts:AssumeRole + self-manage credentials (needed for rotate-root)
POLICY_NAME="VaultAssumedStsPolicy"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

cat > /tmp/vault-assumed-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:role/vault-assume"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetUser",
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:ListAccessKeys"
      ],
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:user/vault-assumed"
    }
  ]
}
EOF

if aws iam get-policy --policy-arn "$POLICY_ARN" &>/dev/null; then
    echo "Policy $POLICY_NAME already exists, creating new version..."
    OLD_VERSION=$(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
        --query 'Versions[?IsDefaultVersion==`false`]|[-1].VersionId' --output text)
    if [ "$OLD_VERSION" != "None" ] && [ -n "$OLD_VERSION" ]; then
        aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$OLD_VERSION" 2>/dev/null || true
    fi
    aws iam create-policy-version --policy-arn "$POLICY_ARN" \
        --policy-document file:///tmp/vault-assumed-policy.json --set-as-default
else
    aws iam create-policy --policy-name "$POLICY_NAME" \
        --policy-document file:///tmp/vault-assumed-policy.json
fi

aws iam attach-user-policy --user-name "$IAM_USER" --policy-arn "$POLICY_ARN"
echo "Policy $POLICY_NAME attached to $IAM_USER."

# Delete all existing access keys
echo ""
echo "Cleaning up old access keys..."
for old_key in $(aws iam list-access-keys --user-name "$IAM_USER" --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
    echo "  Deleting key: $old_key"
    aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$old_key"
done

# Create a new access key
echo ""
echo "Creating new access key..."
aws iam create-access-key --user-name "$IAM_USER" \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' \
    --output text | while read key secret; do
    echo "VAULT_ASSUMED_ACCESS_KEY=$key"
    echo "VAULT_ASSUMED_SECRET_KEY=$secret"
done
```

    Account ID: 220065406052
    User:       vault-assumed
    {
        "User": {
            "Path": "/",
            "UserName": "vault-assumed",
            "UserId": "AIDATGPHLTRSP4D4WZ4Z7",
            "Arn": "arn:aws:iam::220065406052:user/vault-assumed",
            "CreateDate": "2026-02-18T15:39:19+00:00"
        }
    }
    IAM user created.
    {
        "Policy": {
            "PolicyName": "VaultAssumedStsPolicy",
            "PolicyId": "ANPATGPHLTRSLX7EIM4WU",
            "Arn": "arn:aws:iam::220065406052:policy/VaultAssumedStsPolicy",
            "Path": "/",
            "DefaultVersionId": "v1",
            "AttachmentCount": 0,
            "PermissionsBoundaryUsageCount": 0,
            "IsAttachable": true,
            "CreateDate": "2026-02-18T15:39:21+00:00",
            "UpdateDate": "2026-02-18T15:39:21+00:00"
        }
    }
    Policy VaultAssumedStsPolicy attached to vault-assumed.
    
    Cleaning up old access keys...
    
    Creating new access key...
    VAULT_ASSUMED_ACCESS_KEY=AKIATGPHLTRSO7C2EPKP
    VAULT_ASSUMED_SECRET_KEY=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


### Step 2 — Set `vault-assumed` Credentials & Enable `aws-assumed` Mount
Copy the `VAULT_ASSUMED_ACCESS_KEY` and `VAULT_ASSUMED_SECRET_KEY` values from above.


```python
%env VAULT_ASSUMED_ACCESS_KEY=AKIATGPHLTRSO7C2EPKP
%env VAULT_ASSUMED_SECRET_KEY=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
```

    env: VAULT_ASSUMED_ACCESS_KEY=AKIATGPHLTRSO7C2EPKP
    env: VAULT_ASSUMED_SECRET_KEY=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



```bash
%%bash
# Enable a separate AWS secrets engine mount
vault secrets enable -path=aws-assumed aws 2>/dev/null || echo "Mount aws-assumed already enabled."

# Configure root credentials with vault-assumed user
vault write aws-assumed/config/root \
    access_key=$VAULT_ASSUMED_ACCESS_KEY \
    secret_key=$VAULT_ASSUMED_SECRET_KEY \
    region=$REGION \
    rotation_window="1h" \
    rotation_schedule="0 * * * SAT"

echo "Mount aws-assumed configured with vault-assumed credentials."
```

    Success! Enabled the aws secrets engine at: aws-assumed/
    Success! Data written to: aws-assumed/config/root
    Mount aws-assumed configured with vault-assumed credentials.


### Rotate root account


```python
! vault write -f aws-assumed/config/rotate-root
```

    [0mKey           Value
    ---           -----
    access_key    AKIATGPHLTRSDL5LIGFL[0m


![image.png](Personal_AWS_Secret_Engine_files/image.png)

### Step 3 — Create `vault-assume` IAM Role
This role is what Vault will assume (via STS) to manage `test-assumed`'s access keys.  
The trust policy allows `vault-assumed` to assume it.


```bash
%%bash
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
ROLE_NAME="vault-assume"

echo "=== Create IAM Role '$ROLE_NAME' ==="

# Trust policy: allow vault-assumed to assume this role
cat > /tmp/vault-assume-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:user/vault-assumed"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Permissions: manage test-assumed user's access keys + create/delete dynamic users (vault-*)
# Note: iam:GetUser needs "*" because Vault calls GetUser without a username
# first to discover the caller's identity before managing the target user.
cat > /tmp/vault-assume-permissions.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:GetUser",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:ListAccessKeys"
      ],
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:user/test-assumed"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
        "iam:CreateUser",
        "iam:DeleteAccessKey",
        "iam:DeleteUser",
        "iam:DeleteUserPolicy",
        "iam:DetachUserPolicy",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListUserPolicies",
        "iam:PutUserPolicy",
        "iam:AddUserToGroup",
        "iam:RemoveUserFromGroup",
        "iam:TagUser"
      ],
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:user/vault-*"
    }
  ]
}
EOF

if aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
    echo "IAM role $ROLE_NAME already exists, updating trust policy..."
    aws iam update-assume-role-policy --role-name "$ROLE_NAME" \
        --policy-document file:///tmp/vault-assume-trust-policy.json
else
    aws iam create-role --role-name "$ROLE_NAME" \
        --assume-role-policy-document file:///tmp/vault-assume-trust-policy.json
    echo "IAM role $ROLE_NAME created."
fi

aws iam put-role-policy --role-name "$ROLE_NAME" \
    --policy-name "ManageTestAssumed" \
    --policy-document file:///tmp/vault-assume-permissions.json
echo "Inline policy 'ManageTestAssumed' attached to role $ROLE_NAME."
echo "Role ARN: arn:aws:iam::${ACCOUNT_ID}:role/$ROLE_NAME"
```

    === Create IAM Role 'vault-assume' ===
    {
        "Role": {
            "Path": "/",
            "RoleName": "vault-assume",
            "RoleId": "AROATGPHLTRSLW5K54YAR",
            "Arn": "arn:aws:iam::220065406052:role/vault-assume",
            "CreateDate": "2026-02-18T15:40:42+00:00",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::220065406052:user/vault-assumed"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
        }
    }
    IAM role vault-assume created.
    Inline policy 'ManageTestAssumed' attached to role vault-assume.
    Role ARN: arn:aws:iam::220065406052:role/vault-assume


### Step 4 — Create `test-assumed` IAM User
The application user whose access keys Vault will manage via the assumed role.


```bash
%%bash
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
IAM_USER="test-assumed"

echo "Account ID: $ACCOUNT_ID"
echo "User:       $IAM_USER"

# Create IAM user (skip if already exists)
if aws iam get-user --user-name "$IAM_USER" &>/dev/null; then
    echo "IAM user $IAM_USER already exists, skipping creation."
else
    aws iam create-user --user-name "$IAM_USER"
    echo "IAM user $IAM_USER created."
fi

# Attach a simple EC2 read-only policy
APP_POLICY_NAME="TestAssumedEC2ReadOnly"
APP_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${APP_POLICY_NAME}"

cat > /tmp/test-assumed-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeInstances",
        "kms:ListKeys",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
EOF

if aws iam get-policy --policy-arn "$APP_POLICY_ARN" &>/dev/null; then
    echo "Policy $APP_POLICY_NAME already exists, creating new version..."
    OLD_VERSION=$(aws iam list-policy-versions --policy-arn "$APP_POLICY_ARN" \
        --query 'Versions[?IsDefaultVersion==`false`]|[-1].VersionId' --output text)
    if [ "$OLD_VERSION" != "None" ] && [ -n "$OLD_VERSION" ]; then
        aws iam delete-policy-version --policy-arn "$APP_POLICY_ARN" --version-id "$OLD_VERSION" 2>/dev/null || true
    fi
    aws iam create-policy-version --policy-arn "$APP_POLICY_ARN" \
        --policy-document file:///tmp/test-assumed-policy.json --set-as-default
else
    aws iam create-policy --policy-name "$APP_POLICY_NAME" \
        --policy-document file:///tmp/test-assumed-policy.json
fi

aws iam attach-user-policy --user-name "$IAM_USER" --policy-arn "$APP_POLICY_ARN"
echo "Policy $APP_POLICY_NAME attached to $IAM_USER."

# Clean up old access keys and create an initial one
echo ""
echo "Cleaning up old access keys..."
for old_key in $(aws iam list-access-keys --user-name "$IAM_USER" --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
    echo "  Deleting key: $old_key"
    aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$old_key"
done

echo ""
echo "Creating initial access key for $IAM_USER..."
aws iam create-access-key --user-name "$IAM_USER" \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' \
    --output text | while read key secret; do
    echo "Initial Access Key: $key"
    echo "(Vault will rotate this via the assumed role)"
done
```

    Account ID: 220065406052
    User:       test-assumed
    {
        "User": {
            "Path": "/",
            "UserName": "test-assumed",
            "UserId": "AIDATGPHLTRSFV432NM2U",
            "Arn": "arn:aws:iam::220065406052:user/test-assumed",
            "CreateDate": "2026-02-18T15:40:54+00:00"
        }
    }
    IAM user test-assumed created.
    {
        "Policy": {
            "PolicyName": "TestAssumedEC2ReadOnly",
            "PolicyId": "ANPATGPHLTRSJ6OHXX7MC",
            "Arn": "arn:aws:iam::220065406052:policy/TestAssumedEC2ReadOnly",
            "Path": "/",
            "DefaultVersionId": "v1",
            "AttachmentCount": 0,
            "PermissionsBoundaryUsageCount": 0,
            "IsAttachable": true,
            "CreateDate": "2026-02-18T15:40:56+00:00",
            "UpdateDate": "2026-02-18T15:40:56+00:00"
        }
    }
    Policy TestAssumedEC2ReadOnly attached to test-assumed.
    
    Cleaning up old access keys...
    
    Creating initial access key for test-assumed...
    Initial Access Key: AKIATGPHLTRSCY52WNGV
    (Vault will rotate this via the assumed role)


### Step 5 — Create Static Role on `aws-assumed` Mount
The static role maps to `test-assumed` and uses `assume_role_arn` so Vault will assume `vault-assume` to manage the keys.


```bash
%%bash
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

vault write aws-assumed/static-roles/test-assumed \
    username=test-assumed \
    rotation_period=1h \
    assume_role_arn="arn:aws:iam::${ACCOUNT_ID}:role/vault-assume" \
    assume_role_session_name="vault-session"


```

    Key                         Value
    ---                         -----
    assume_role_arn             arn:aws:iam::220065406052:role/vault-assume
    assume_role_session_name    vault-session
    external_id                 n/a
    id                          AIDATGPHLTRSFV432NM2U
    name                        test-assumed
    rotation_period             1h
    username                    test-assumed


![image.png](Personal_AWS_Secret_Engine_files/image.png)


```bash
%%bash
echo "Static role created. Reading config:"
vault read aws-assumed/static-roles/test-assumed
```

    Static role created. Reading config:
    Key                         Value
    ---                         -----
    assume_role_arn             arn:aws:iam::220065406052:role/vault-assume
    assume_role_session_name    vault-session
    external_id                 n/a
    id                          AIDATGPHLTRSFV432NM2U
    name                        test-assumed
    rotation_period             1h
    username                    test-assumed



```python
! vault read aws-assumed/static-creds/test-assumed
```

    [0mKey           Value
    ---           -----
    access_key    AKIATGPHLTRSPB2T3H5C
    expiration    2026-02-18T16:41:18.541424866Z
    secret_key    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[0m


### Step 6 — Verification
Read the static credentials from `aws-assumed` mount and test them against AWS.


```bash
%%bash
echo "=== Static Credentials (test-assumed via vault-assume role) ==="

# Use the static credentials to call AWS
CREDS=$(vault read -format=json aws-assumed/static-creds/test-assumed)
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.data.access_key')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.data.secret_key')
unset AWS_SESSION_TOKEN

echo "Access Key: $AWS_ACCESS_KEY_ID"

# Wait for AWS IAM to propagate the new key (eventual consistency)
echo "Waiting 10s for AWS IAM propagation..."
sleep 10

echo "=== Caller Identity (using test-assumed static creds) ==="
aws sts get-caller-identity

echo ""

echo "=== EC2 Describe Regions ==="
aws ec2 describe-regions --query 'Regions[*].RegionName' --output table --region $REGION

echo ""

echo "=== EC2 Describe Instances ==="
aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,State:State.Name,AZ:Placement.AvailabilityZone,Name:Tags[?Key==`Name`]|[0].Value}' \
    --output table --region $REGION

echo ""

echo "=== KMS List Keys ==="
aws kms list-keys --query 'Keys[*].KeyId' --output table --region $REGION

echo ""

echo "=== Static Role Config ==="
vault read aws-assumed/static-roles/test-assumed
```

    === Static Credentials (test-assumed via vault-assume role) ===
    Access Key: AKIATGPHLTRSPB2T3H5C
    Waiting 10s for AWS IAM propagation...
    === Caller Identity (using test-assumed static creds) ===
    {
        "UserId": "AIDATGPHLTRSFV432NM2U",
        "Account": "220065406052",
        "Arn": "arn:aws:iam::220065406052:user/test-assumed"
    }
    
    === EC2 Describe Regions ===
    --------------------
    |  DescribeRegions |
    +------------------+
    |  ap-south-1      |
    |  eu-north-1      |
    |  eu-west-3       |
    |  eu-west-2       |
    |  eu-south-2      |
    |  eu-west-1       |
    |  ap-northeast-3  |
    |  ap-northeast-2  |
    |  ap-northeast-1  |
    |  ca-central-1    |
    |  sa-east-1       |
    |  ap-southeast-1  |
    |  ap-southeast-2  |
    |  eu-central-1    |
    |  us-east-1       |
    |  us-east-2       |
    |  us-west-1       |
    |  us-west-2       |
    +------------------+
    
    === EC2 Describe Instances ===
    
    === KMS List Keys ===
    
    === Static Role Config ===
    Key                         Value
    ---                         -----
    assume_role_arn             arn:aws:iam::220065406052:role/vault-assume
    assume_role_session_name    vault-session
    external_id                 n/a
    id                          AIDATGPHLTRSFV432NM2U
    name                        test-assumed
    rotation_period             1h
    username                    test-assumed


# Dynamic Credentials

### On aws mount (stati cred without assumed role)


```bash
%%bash
# Create a Vault role that generates dynamic IAM users with EC2/KMS read-only permissions
vault write aws/roles/dynamic-readonly \
    credential_type=iam_user \
    policy_document='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeInstances",
        "kms:ListKeys",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}'

echo ""
echo "Role created. Reading config:"
vault read aws/roles/dynamic-readonly
```

    Success! Data written to: aws/roles/dynamic-readonly
    
    Role created. Reading config:
    Key                         Value
    ---                         -----
    credential_type             iam_user
    default_sts_ttl             0s
    external_id                 n/a
    iam_groups                  <nil>
    iam_tags                    <nil>
    max_sts_ttl                 0s
    mfa_serial_number           n/a
    permissions_boundary_arn    n/a
    policy_arns                 <nil>
    policy_document             {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:DescribeRegions","ec2:DescribeInstances","kms:ListKeys","sts:GetCallerIdentity"],"Resource":"*"}]}
    role_arns                   <nil>
    session_tags                <nil>
    user_path                   n/a


#### Validation


```bash
%%bash
# Generate dynamic credentials
echo "=== Generate Dynamic Credentials ==="
CREDS=$(vault read -format=json aws/creds/dynamic-readonly)
echo "$CREDS" | jq '.data | {access_key, secret_key, security_token: (.security_token // "none")} + {lease_id: .lease_id}'

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.data.access_key')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.data.secret_key')
unset AWS_SESSION_TOKEN

LEASE_ID=$(echo $CREDS | jq -r '.lease_id')

# Wait for AWS IAM propagation
echo ""
echo "Waiting 10s for AWS IAM propagation..."
sleep 10

echo "=== Caller Identity (dynamic creds) ==="
aws sts get-caller-identity

echo ""

echo "=== EC2 Describe Regions ==="
aws ec2 describe-regions --query 'Regions[*].RegionName' --output table --region $REGION

echo ""

echo "=== EC2 Describe Instances ==="
aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,State:State.Name,AZ:Placement.AvailabilityZone,Name:Tags[?Key==`Name`]|[0].Value}' \
    --output table --region $REGION

echo ""

echo "=== KMS List Keys ==="
aws kms list-keys --query 'Keys[*].KeyId' --output table --region $REGION

echo ""
echo "Lease ID: $LEASE_ID"
echo "To revoke: vault lease revoke $LEASE_ID"
```

    === Generate Dynamic Credentials ===
    {
      "access_key": "AKIATGPHLTRSEQRS4CPH",
      "secret_key": "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",
      "security_token": "none",
      "lease_id": null
    }
    
    Waiting 10s for AWS IAM propagation...
    === Caller Identity (dynamic creds) ===
    {
        "UserId": "AIDATGPHLTRSAFXYF5AVU",
        "Account": "220065406052",
        "Arn": "arn:aws:iam::220065406052:user/vault-token-dynamic-readonly-1771429408-EUpVKzX6lOR47aykbuKH"
    }
    
    === EC2 Describe Regions ===
    --------------------
    |  DescribeRegions |
    +------------------+
    |  ap-south-1      |
    |  eu-north-1      |
    |  eu-west-3       |
    |  eu-west-2       |
    |  eu-south-2      |
    |  eu-west-1       |
    |  ap-northeast-3  |
    |  ap-northeast-2  |
    |  ap-northeast-1  |
    |  ca-central-1    |
    |  sa-east-1       |
    |  ap-southeast-1  |
    |  ap-southeast-2  |
    |  eu-central-1    |
    |  us-east-1       |
    |  us-east-2       |
    |  us-west-1       |
    |  us-west-2       |
    +------------------+
    
    === EC2 Describe Instances ===
    
    === KMS List Keys ===
    
    Lease ID: aws/creds/dynamic-readonly/kpA32Ojx6lOBXUaaXPEYfRA7
    To revoke: vault lease revoke aws/creds/dynamic-readonly/kpA32Ojx6lOBXUaaXPEYfRA7


![image.png](Personal_AWS_Secret_Engine_files/image.png)


```bash
%%bash
# Revoke the dynamic credentials (deletes the temporary IAM user)
echo "=== Revoking all dynamic leases ==="
vault lease revoke -prefix aws/creds/dynamic-readonly
echo "All dynamic credentials revoked."
```

    === Revoking all dynamic leases ===
    All revocation operations queued successfully!
    All dynamic credentials revoked.


### With Assume role


```bash
%%bash
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# Create a Vault role on aws-assumed that generates dynamic IAM users via the assumed role
vault write aws-assumed/roles/dynamic-assumed-readonly \
    credential_type=iam_user \
    assume_role_arn="arn:aws:iam::${ACCOUNT_ID}:role/vault-assume" \
    policy_document='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeInstances",
        "kms:ListKeys",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}'

echo ""
echo "Role created. Reading config:"
vault read aws-assumed/roles/dynamic-assumed-readonly
```

    Success! Data written to: aws-assumed/roles/dynamic-assumed-readonly
    
    Role created. Reading config:
    Key                         Value
    ---                         -----
    credential_type             iam_user
    default_sts_ttl             0s
    external_id                 n/a
    iam_groups                  <nil>
    iam_tags                    <nil>
    max_sts_ttl                 0s
    mfa_serial_number           n/a
    permissions_boundary_arn    n/a
    policy_arns                 <nil>
    policy_document             {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:DescribeRegions","ec2:DescribeInstances","kms:ListKeys","sts:GetCallerIdentity"],"Resource":"*"}]}
    role_arns                   <nil>
    session_tags                <nil>
    user_path                   n/a


### Test Dynamic Credentials (Assumed Role)


```bash
%%bash
# Generate dynamic credentials via the assumed role
echo "=== Generate Dynamic Credentials (via vault-assume role) ==="
CREDS=$(vault read -format=json aws-assumed/creds/dynamic-assumed-readonly)
echo "$CREDS" | jq '.data | {access_key, secret_key}'

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.data.access_key')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.data.secret_key')
unset AWS_SESSION_TOKEN

LEASE_ID=$(echo $CREDS | jq -r '.lease_id')

# Wait for AWS IAM propagation
echo ""
echo "Waiting 10s for AWS IAM propagation..."
sleep 10

echo "=== Caller Identity (dynamic creds via assumed role) ==="
aws sts get-caller-identity

echo ""

echo "=== EC2 Describe Regions ==="
aws ec2 describe-regions --query 'Regions[*].RegionName' --output table --region $REGION

echo ""

echo "=== EC2 Describe Instances ==="
aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,State:State.Name,AZ:Placement.AvailabilityZone,Name:Tags[?Key==`Name`]|[0].Value}' \
    --output table --region $REGION

echo ""

echo "=== KMS List Keys ==="
aws kms list-keys --query 'Keys[*].KeyId' --output table --region $REGION

echo ""
echo "Lease ID: $LEASE_ID"
echo "To revoke: vault lease revoke $LEASE_ID"
```

    === Generate Dynamic Credentials (via vault-assume role) ===
    {
      "access_key": "AKIATGPHLTRSB3BHDTWC",
      "secret_key": "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"
    }
    
    Waiting 10s for AWS IAM propagation...
    === Caller Identity (dynamic creds via assumed role) ===
    {
        "UserId": "AIDATGPHLTRSMMDC5PRLU",
        "Account": "220065406052",
        "Arn": "arn:aws:iam::220065406052:user/vault-token-dynamic-assumed-readonly-1771429489-39voelPSLoaMSspm"
    }
    
    === EC2 Describe Regions ===
    --------------------
    |  DescribeRegions |
    +------------------+
    |  ap-south-1      |
    |  eu-north-1      |
    |  eu-west-3       |
    |  eu-west-2       |
    |  eu-south-2      |
    |  eu-west-1       |
    |  ap-northeast-3  |
    |  ap-northeast-2  |
    |  ap-northeast-1  |
    |  ca-central-1    |
    |  sa-east-1       |
    |  ap-southeast-1  |
    |  ap-southeast-2  |
    |  eu-central-1    |
    |  us-east-1       |
    |  us-east-2       |
    |  us-west-1       |
    |  us-west-2       |
    +------------------+
    
    === EC2 Describe Instances ===
    
    === KMS List Keys ===
    
    Lease ID: aws-assumed/creds/dynamic-assumed-readonly/fTrpJqEKgtKn0cSZtKrIoYig
    To revoke: vault lease revoke aws-assumed/creds/dynamic-assumed-readonly/fTrpJqEKgtKn0cSZtKrIoYig


![image.png](Personal_AWS_Secret_Engine_files/image.png)


```bash
%%bash
# Revoke the dynamic credentials (deletes the temporary IAM user)
echo "=== Revoking all dynamic leases (assumed role) ==="
vault lease revoke -prefix aws-assumed/creds/dynamic-assumed-readonly
echo "All dynamic credentials revoked."
```

    === Revoking all dynamic leases (assumed role) ===
    All revocation operations queued successfully!
    All dynamic credentials revoked.


# Clean up


```bash
%%bash
echo "=== Deleting Vault static roles and mounts ==="
vault delete aws/static-roles/app-test 2>/dev/null && echo "Deleted static role aws/static-roles/app-test" || true
vault delete aws-assumed/static-roles/test-assumed 2>/dev/null && echo "Deleted static role aws-assumed/static-roles/test-assumed" || true
vault secrets disable aws 2>/dev/null && echo "Disabled mount aws/" || true
vault secrets disable aws-assumed 2>/dev/null && echo "Disabled mount aws-assumed/" || true
echo "Done."
```

    === Deleting Vault static roles and mounts ===
    Success! Data deleted (if it existed) at: aws/static-roles/app-test
    Deleted static role aws/static-roles/app-test
    Success! Data deleted (if it existed) at: aws-assumed/static-roles/test-assumed
    Deleted static role aws-assumed/static-roles/test-assumed
    Success! Disabled the secrets engine (if it existed) at: aws/
    Disabled mount aws/
    Success! Disabled the secrets engine (if it existed) at: aws-assumed/
    Disabled mount aws-assumed/
    Done.



```bash
%%bash
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

echo "=== Deleting IAM Users ==="
for USER in vault-root app-test vault-assumed test-assumed; do
    echo ""
    echo "--- Deleting user: $USER ---"

    # Delete access keys
    for KEY in $(aws iam list-access-keys --user-name "$USER" --query 'AccessKeyMetadata[*].AccessKeyId' --output text 2>/dev/null); do
        aws iam delete-access-key --user-name "$USER" --access-key-id "$KEY"
        echo "  Deleted access key: $KEY"
    done

    # Detach managed policies
    for POLICY_ARN in $(aws iam list-attached-user-policies --user-name "$USER" --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null); do
        aws iam detach-user-policy --user-name "$USER" --policy-arn "$POLICY_ARN"
        echo "  Detached policy: $POLICY_ARN"
    done

    # Delete inline policies
    for POLICY_NAME in $(aws iam list-user-policies --user-name "$USER" --query 'PolicyNames[*]' --output text 2>/dev/null); do
        aws iam delete-user-policy --user-name "$USER" --policy-name "$POLICY_NAME"
        echo "  Deleted inline policy: $POLICY_NAME"
    done

    # Delete the user
    aws iam delete-user --user-name "$USER" 2>/dev/null && echo "  User $USER deleted." || echo "  User $USER not found or already deleted."
done

echo ""
echo "=== Deleting IAM Role: vault-assume ==="
ROLE_NAME="vault-assume"

# Delete inline policies from the role
for POLICY_NAME in $(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames[*]' --output text 2>/dev/null); do
    aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME"
    echo "  Deleted inline policy: $POLICY_NAME"
done

# Detach managed policies from the role
for POLICY_ARN in $(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null); do
    aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN"
    echo "  Detached policy: $POLICY_ARN"
done

aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null && echo "  Role $ROLE_NAME deleted." || echo "  Role $ROLE_NAME not found or already deleted."

echo ""
echo "=== Deleting IAM Policies ==="
for POLICY_NAME in VaultIAMPolicy AppTestEC2ReadOnly VaultAssumedStsPolicy TestAssumedEC2ReadOnly; do
    POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"
    # Delete all non-default policy versions first
    for VERSION in $(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
        --query 'Versions[?IsDefaultVersion==`false`].VersionId' --output text 2>/dev/null); do
        aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$VERSION"
        echo "  Deleted version $VERSION of $POLICY_NAME"
    done
    aws iam delete-policy --policy-arn "$POLICY_ARN" 2>/dev/null && echo "  Policy $POLICY_NAME deleted." || echo "  Policy $POLICY_NAME not found or already deleted."
done

echo ""
echo "=== AWS cleanup complete ==="
```

    === Deleting IAM Users ===
    
    --- Deleting user: vault-root ---
      Deleted access key: AKIATGPHLTRSLWPMOMVS
      Detached policy: arn:aws:iam::220065406052:policy/VaultIAMPolicy
      User vault-root deleted.
    
    --- Deleting user: app-test ---
      Deleted access key: AKIATGPHLTRSCRNOWHGM
      Detached policy: arn:aws:iam::220065406052:policy/AppTestEC2ReadOnly
      User app-test deleted.
    
    --- Deleting user: vault-assumed ---
      Deleted access key: AKIATGPHLTRSDL5LIGFL
      Detached policy: arn:aws:iam::220065406052:policy/VaultAssumedStsPolicy
      User vault-assumed deleted.
    
    --- Deleting user: test-assumed ---
      Deleted access key: AKIATGPHLTRSCY52WNGV
      Detached policy: arn:aws:iam::220065406052:policy/TestAssumedEC2ReadOnly
      User test-assumed deleted.
    
    === Deleting IAM Role: vault-assume ===
      Deleted inline policy: ManageTestAssumed
      Role vault-assume deleted.
    
    === Deleting IAM Policies ===
      Policy VaultIAMPolicy deleted.
      Policy AppTestEC2ReadOnly deleted.
      Policy VaultAssumedStsPolicy deleted.
      Policy TestAssumedEC2ReadOnly deleted.
    
    === AWS cleanup complete ===



```bash
%%bash
echo "=== Stopping Vault container ==="
podman stop vault-enterprise 2>/dev/null && echo "Vault container stopped." || echo "Vault container not running."
echo "=== All demo resources cleaned up ==="
```

    === Stopping Vault container ===
    vault-enterprise
    Vault container stopped.
    === All demo resources cleaned up ===

