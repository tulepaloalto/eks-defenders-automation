# EKS Defender Deployment Automation Requirements:

## Configuration

### General Configuration 
![alt text](https://github.com/tulepaloalto/eks-defenders-automation/blob/main/readmepics/Screenshot%202024-09-10%20at%204.11.54%E2%80%AFPM.png)

The timeout at 10 minutes is fine for testing, but should set to an hour for standard deployment.

## Permissions/Role

Create a role for the Lambda Function, the Role should have these policies:

•	EKS - Full Access

•	Secrets Manager - Read Access

### VPC 

•	The VPC should be the same VPC as the EKS clusters' VPC

•	The VPC should be able to talk to the Secrets Manager

•	The VPC should be able to connect to the Internet to call Prisma Cloud's API

## Environment Variables
	
    AWS_ACCESS_POLICY_ARN: Should be the ARN of the AmazonEKSClusterAdminPolicy

    AWS_AUTOMATION_SECRET_NAME: This is the name of the Secret object in Secret Manager

    AWS_ROLE_ARN: This is the role assigned to the Lambda function

    CONSOLE_ADDRESS: This can be found in the Prisma Cloud console (Runtime Security -> System -> Utilities -> Path to Console), only keep the url before twistlock.com 

    CSPM_ADDRESS: This should be your Prisma Cloud console URL, change app to api.

    CWP_ENDPOINT: Same as Console Address location, but it’s the exact path.

    REGION: The region of the EKS clusters

    ##Secrets Manager
	
	•	The access key and secret key can be created in the Prisma Cloud console (Settings -> Access Control -> Access key)
