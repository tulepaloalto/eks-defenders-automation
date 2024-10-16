# pylint: disable=too-many-lines, import-error, line-too-long
"""
TODO: update docstring
This file contains a collection of Prisma helper functions for automating tasks.

Functions:
- aws_initiate_secrets_manager_client()
- aws_secrets_manager_get_secret()

Usage:
- Simply import this file and call the function. For example:

    from prisma_implementation_functions import generate_prisma_token

Notes:
- Before using these functions, be sure to configure the .env appropriately.

"""
import boto3
import logging
import datetime
from typing import Optional
import sh
import yaml
import tempfile
import base64
import time
from eks_token import get_token
import subprocess
from kubernetes import client, config, utils
from botocore.exceptions import ClientError

def aws_initiate_session():
    """
    Initiate the AWS Session.

    Returns:
        AWS Session
    """
    session = boto3.session.Session()
    return session

def aws_initiate_eks_session(assumed_role_creds):
    """
    Initiate the AWS Session.

    Returns:
        AWS Session
    """
    session = boto3.session.Session(
        aws_access_key_id=assumed_role_creds["AccessKeyId"],
        aws_secret_access_key=assumed_role_creds["SecretAccessKey"],
        aws_session_token=assumed_role_creds["SessionToken"]
    )
    return session

def aws_initiate_secrets_manager_client(
         session, region: Optional[str] = ""
):
    """
    Initiate the AWS Secret Manager client.

    Returns:
        AWS Secret Manager Client
    """
    client = session.client(
        service_name='secretsmanager',
        region_name=region
    )
    return client

def aws_initiate_ecs_client(
        session, region: Optional[str] = ""
):
    """
    Initiate the AWS Secret Manager client.

    Returns:
        AWS Secret Manager Client
    """
    client = session.client(
        service_name='ecs',
        region_name=region
    )
    return client

def aws_initiate_eks_client(
        session, region: Optional[str] = ""
):
    """
    Initiate the AWS Secret Manager client.

    Returns:
        AWS Secret Manager Client
    """
    client = session.client(
        service_name='eks',
        region_name=region
    )
    return client

def aws_initiate_lambda_client(
        session, region: Optional[str] = ""
):
    """
    Initiate the AWS Secret Manager client.

    Returns:
        AWS Secret Manager Client
    """
    client = session.client(
        service_name='lambda',
        region_name=region
    )
    return client

def aws_initiate_sts_client(
        session, region: Optional[str] = ""
):
    """
    Initiate the AWS STS client.

    Returns:
        AWS Secret Manager Client
    """
    client = session.client(
        service_name='sts',
        region_name=region
    )
    return client

def aws_initiate_kubernetes_api_client(cluster, debug_mode: bool):
    """
    Get cluster configurations from AWS EKS

    Args:
        client: AWS EKS client
        cluster_name: AWS Cluster Name

    Raises:
        ex: Client Error

    Returns:
        object: EKS Cluster
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
        
    logging.info("Initiate Kubernetes API Client")
    cluster_cert = cluster["cluster"]["certificateAuthority"]["data"]
    cluster_ep = cluster["cluster"]["endpoint"]
    cluster_name = cluster["cluster"]["name"]
    logging.info("Cluster {}".format(cluster_name))

    try:
        #config.load_kube_config(config_file='/tmp/config')
        cafile = tempfile.NamedTemporaryFile(delete=False)
        cadata_b64 = str(cluster_cert)
        cadata = base64.b64decode(cadata_b64)
        cafile.write(cadata)
        cafile.flush()
        token = get_token(cluster_name)['status']['token']
        kconfig = config.kube_config.Configuration(
            host=cluster_ep,
            api_key={'authorization': 'Bearer ' + token}
        )
        kconfig.ssl_ca_cert = cafile.name
        kclient = client.ApiClient(configuration=kconfig)
        api_client = client.CoreV1Api(api_client=kclient)
    except Exception as e:
        logging.info(e)

    return api_client, kclient

def aws_ecs_get_clusters(client, debug_mode: bool) -> list:
    """
    Get all ECS clusters

    Args:
        client: AWS ECS client

    Raises:
        ex: Client Error

    Returns:
        object: List of all ECS clusters
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    try:
        clusters = []
        paginator = client.get_paginator('list_clusters')
        for page in paginator.paginate():
            clusters.extend(page['clusterArns'])
        response=clusters
        logging.info("All ECS Clusters retrieved.")

    except ClientError as ex:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise ex

    return response

def aws_ecs_get_services(cluster_name: str, client, debug_mode: bool):
    """
    Retrieve all services within a specified ECS cluster
    Args:
        client: AWS ECS client
        layer_arn: AWS Layer Arn
    Raises:
        ex: Client Error

    Returns:
        object: Lambda twistlock layer
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    try:
        services = []
        paginator = client.get_paginator('list_services')
        for page in paginator.paginate(cluster=cluster_name):
            services.extend(page['serviceArns'])
            response=services

    except ClientError as ex:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise ex

    return response

def aws_ecs_get_service_desc(service_arn, cluster_name, client, debug_mode: bool):
    """
    Get service description from AWS
    Args:
        client: AWS ECS client
        service_arn: Service ARN
        cluster_name: Cluster Name
    Raises:
        ex: Client Error

    Returns:
        Object: service
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    try:
        response = client.describe_services(cluster=cluster_name, services=[service_arn])
    except ClientError as ex:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise ex

    return response

def aws_ecs_is_fargate_service(service_desc, debug_mode: bool):
    """
    Check to see if Service is Fargate Service
    Args:
        client: AWS ECS client
        service_arn: Service ARN
        cluster_name: Name of ECS cluster
    Raises:
        ex: Client Error

    Returns:
        bool
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    response = False
    if 'services' in service_desc and len(service_desc['services']) > 0:
        for service in service_desc['services']:
            if 'capacityProviderStrategy' in service:
                for capacityProviderStrategy in service['capacityProviderStrategy']:
                    if capacityProviderStrategy['capacityProvider'] == 'FARGATE' and capacityProviderStrategy['weight'] > 0:
                        response = True
            
            elif 'launchType' in service:
                if service['launchType'] == "FARGATE":
                    response = True

    return service, response
    
def aws_ecs_get_fargate_defender_status(latest_version, task_definition_arn, client, debug_mode: bool):
    """
    Check to see if Fargate Service is defended, outdated, or not
    Args:
        client: AWS ECS client
        task_definition_arn: task_definition ARN
    Raises:
        ex: Client Error

    Returns:
        String - defended/outdated/undefended
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    try:
        response = "undefended"
        task_definition_desc = client.describe_task_definition(taskDefinition=task_definition_arn)
        task_definition = task_definition_desc['taskDefinition']

        for container in task_definition['containerDefinitions']:
            if container['name'] == "TwistlockDefender":
                defender_version = container["image"][-9:]               
                if defender_version == latest_version:
                    response = "defended"
                else:
                    response = "outdated"
                    logging.info(f"Current Defender Version is {defender_version}, the newest version is {latest_version}. Initiating update...")                   
                break

    except ClientError as ex:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise ex
    
    if response == "undefended":
        logging.info("Task definition is not defended, defender deployment starting.")

    return task_definition, response

def aws_ecs_register_task_definition(task_definition: str, client, debug_mode: bool):
    """
    Register a new ECS task definition
    Args:
        client: AWS Client client
        layer_arn: AWS Layer Arn

    Raises:
        ex: Client Error

    Returns:
        object: Lambda twistlock layer
    """
    """Register a new ECS task definition"""
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    try:
        response = client.register_task_definition(**task_definition)
        return response['taskDefinition']['taskDefinitionArn']
    
    except Exception as e:
        logging.info(f"Error registering task definition: {e}")
        return None
    
def aws_ecs_update_service(cluster_name: str, service_name :str, new_task_definition: str, client, debug_mode: bool):
    """
    Register a new ECS task definition
    Args:
        client: AWS Client client
        layer_arn: AWS Layer Arn

    Raises:
        ex: Client Error

    Returns:
        object: Lambda twistlock layer
    """
    """Register a new ECS task definition"""
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    try:
        response = client.update_service(
            cluster=cluster_name,
            service=service_name,
            taskDefinition=new_task_definition
        )
        return response
    except Exception as e:
        logging.info(f"Error updating service: {e}")
        return None

def aws_lambda_get_function(function_name: str, client, debug_mode: bool) -> dict:
    """
    Get function from AWS Lambda

    Args:
        client: AWS Lambda client
        function_name (str): Function Name

    Raises:
        ex: Client Error

    Returns:
        object: Lambda Function
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    logging.info("Getting function {}".format(function_name))
    try:
        response = client.get_function(
            FunctionName=function_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logging.info("The requested function %s was not found", function_name)
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logging.info("The request was invalid due to: %s", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logging.info("The request had invalid params: %s", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            logging.info(
                "The requested secret can't be decrypted using the provided KMS key: %s", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            logging.info("An error occurred on service side: %s", e)

    return response

def aws_lambda_update_function(function_name: str, layer_arn, client, debug_mode: bool) -> dict:
    """
    Get twistlock layer from AWS Lambda

    Args:
        client: AWS Lambda client
        layer_arn: AWS Layer Arn

    Raises:
        ex: Client Error

    Returns:
        object: Lambda twistlock layer
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
        
    logging.info("Updating function with new layer")
    response = client.update_function_configuration(
        FunctionName=function_name,
        Layers=[layer_arn]
    )

    return response

def aws_lambda_get_layer(layer_arn, client, debug_mode: bool) -> dict:
    """
    Get twistlock layer from AWS Lambda

    Args:
        client: AWS Lambda client
        layer_arn: AWS Layer Arn

    Raises:
        ex: Client Error

    Returns:
        object: Lambda twistlock layer
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    logging.info("Getting twistlock layer")
    try:
        response = client.get_layer_version_by_arn(
            Arn=layer_arn
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logging.info("The requested layer %s was not found", layer_arn)
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logging.info("The request was invalid due to: %s", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logging.info("The request had invalid params: %s", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            logging.info(
                "The requested secret can't be decrypted using the provided KMS key: %s", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            logging.info("An error occurred on service side: %s", e)

    return response

def aws_lambda_publish_layer(layer_arn, zip_file, runtimes, client, debug_mode: bool) -> dict:
    """
    Publish twistlock layer from AWS Lambda with new Serverless zip

    Args:
        client: AWS Lambda client
        layer_arn: AWS Layer Arn

    Raises:
        ex: Client Error

    Returns:
        object: Lambda twistlock layer
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )

    logging.info("Publishing twistlock layer")
    response = client.publish_layer_version(
        LayerName=layer_arn,
        Description="Twistlock layer updated by Prisma Automation on {}".format(datetime.datetime.now()),
        Content={
            'ZipFile': zip_file
        },
        CompatibleRuntimes=runtimes
    )

    return response

def aws_secrets_manager_get_secret(client, secret_name: str, debug_mode: bool) -> dict:
    """
    Get secret from AWS Secret Manager

    Args:
        client: AWS Secret Manager client
        secret_name (str): Secret Name

    Raises:
        ex: Client Error

    Returns:
        list: Secret metadata
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    try:
        response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as ex:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise ex

    return response

def aws_secrets_manager_update_secret_value(client, secret_name: str, secret_value: str, debug_mode: bool) -> bool:
    """
    Update secret in AWS Secret Manager

    Args:
        client: AWS Secret Manager client
        secret_name (str): Secret Name
        secret_value (str): Secret Value

    Raises:
        ex: Client Error

    Returns:
        list: Secret metadata
    """
    if debug_mode:
        logging.info(
            "API PUT_REQUEST \u2717: not sending the request.")

        return False

    try:
        response = client.put_secret_value(
            SecretId=secret_name,
            SecretString=secret_value,
        )

        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logging.info("The requested secret %s was not found", secret_name)

    return False

def aws_secrets_manager_create_secret(client, secret_name: str, secret_value: str, debug_mode: bool) -> bool:
    """
    Create secret in AWS Secret Manager

    Args:
        client: AWS Secret Manager client
        secret_name (str): Secret Name
        secret_value (str): Secret Value

    Raises:
        ex: Client Error

    Returns:
        list: Secret metadata
    """
    if debug_mode:
        logging.info(
            "API CREATE_REQUEST \u2717: not sending the request.")

        return False
    try:
        response = client.create_secret(
            Description="Secret managed by Prisma automation.",
            Name=secret_name,
            SecretString=secret_value,
        )

        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logging.info("The requested secret %s was not found", secret_name)

    return False

def aws_eks_describe_cluster(cluster_name: str, client, debug_mode: bool) -> dict:
    """
    Get cluster configurations from AWS EKS

    Args:
        client: AWS EKS client
        cluster_name: AWS Cluster Name

    Raises:
        ex: Client Error

    Returns:
        object: EKS Cluster
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
        
    logging.info("Getting function config")
    try:
        response = client.describe_cluster(
            name=cluster_name,
        )  
    except Exception as e:
        response = "Cluster not found."
        logging.debug(e)

    return response

def aws_eks_list_clusters(client, debug_mode: bool) -> dict:
    """
    Get cluster configurations from AWS EKS

    Args:
        client: AWS EKS client
        cluster_name: AWS Cluster Name

    Raises:
        ex: Client Error

    Returns:
        object: EKS Cluster
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
        
    logging.info("Getting clusters...")
    try:
        response = client.list_clusters(
        )  
    except Exception as e:
        response = "Cluster not found."
        logging.info(e)

    return response["clusters"]

def aws_eks_update_kubeconfig(cluster, region, debug_mode: bool) -> dict:
    """
    Get cluster configurations from AWS EKS

    Args:
        client: AWS EKS client
        cluster_name: AWS Cluster Name

    Raises:
        ex: Client Error

    Returns:
        object: EKS Cluster
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
        
    logging.info("Updating kubeconfig for {}".format(cluster["cluster"]['arn']))

    cluster_cert = cluster["cluster"]["certificateAuthority"]["data"]
    cluster_ep = cluster["cluster"]["endpoint"]
    cluster_arn = cluster["cluster"]["arn"]

    cluster_config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "cluster": {
                    "server": str(cluster_ep),
                    "certificate-authority-data": str(cluster_cert)
                },
                "name": cluster_arn
            }
        ],
        "contexts": [
            {
                "context": {
                    "cluster": cluster_arn,
                    "user": cluster_arn
                },
                "name": cluster_arn
            }
        ],
        "current-context": cluster_arn,
        "preferences": {},
        "users": [
            {
                "name": "aws",
                "user": {
                    "exec": {
                        "apiVersion": "client.authentication.k8s.io/v1beta1",
                        "command": "aws",
                        "args": [
                            "--region", region, "eks", "get-token", "--cluster-name", str(cluster["cluster"]["name"]), "--output", "json"
                        ]
                    }
                }
            }
        ]
    }

    # Write in YAML.
    try:
        config_text=yaml.dump(cluster_config, default_flow_style=False)
        open("/tmp/config", "w").write(config_text)
        #logging.info(open("/tmp/config", "r").readlines())
    except Exception as e:
        logging.info(e)
        
    return "kube-config updated"

def aws_eks_create_access_entry(client, cluster_name, assumed_role_arn, access_policy_arn, debug_mode: bool):
    """
    Create access entry and assign access policies for Cluster

    Args:
        client: AWS EKS client
        cluster_name: AWS Cluster Name

    Raises:
        ex: Client Error

    Returns:
        object: EKS Cluster
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
        
    logging.info("Creating access entry...")
    logging.info("role_arn: {}".format(assumed_role_arn))
    try:
        response = client.create_access_entry(clusterName=cluster_name, principalArn=assumed_role_arn)
        response = client.associate_access_policy(
            clusterName=cluster_name,
            principalArn=assumed_role_arn, 
            policyArn=access_policy_arn,
            accessScope={
                'type': 'cluster'
            }
        )
        time.sleep(30)
    except Exception as e:
        response = "Access Entry already exists. Moving on..."
        logging.info(e)

    return response

def aws_eks_check_access_entry(client, cluster_name, assumed_role_arn, debug_mode: bool):
    """
    Create access entry for Cluster

    Args:
        client: AWS EKS client
        cluster_name: AWS Cluster Name

    Raises:
        ex: Client Error

    Returns:
        object: EKS Cluster
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
        
    logging.info("Check to see if access entry already exists...")
    try:
        response = client.describe_access_entry(
            clusterName=cluster_name,
            principalArn=assumed_role_arn
        )
        if response != None:
            response = True
        else:
            response = False
    except Exception as e:
        logging.info(e)

    return response

def aws_eks_list_access_entry(client, cluster_name, debug_mode: bool):
    """
    List access entries for Cluster

    Args:
        client: AWS EKS client
        cluster_name: AWS Cluster Name

    Raises:
        ex: Client Error

    Returns:
        object: EKS Cluster
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
        
    logging.info("Running CLI commands")
    try:
        access_entries = []
        paginator = client.get_paginator('list_access_entries')
        for page in paginator.paginate(clusterName=cluster_name):
            access_entries.extend(page['accessEntries'])
        response=access_entries
        logging.info("All ECS Clusters retrieved.")
    except Exception as e:
        logging.info(e)

    return response

def aws_cli_taint_nodes(api_client, kclient, debug_mode: bool):
    """
    Get cluster configurations from AWS EKS

    Args:
        client: AWS EKS client
        cluster_name: AWS Cluster Name

    Raises:
        ex: Client Error

    Returns:
        object: EKS Cluster
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
    taint_patch = {"spec": {"taints": [{"effect": "NoSchedule", "key": "kubernetes.io/os", "value": "windows"}]}}
    keys = set()
    try:
        logging.info("list nodes...")
        node_list = api_client.list_node(pretty=True)
        for node in node_list.items:
            if node.metadata.labels["kubernetes.io/os"] == "windows":
                logging.info("windows node: {}".format(node.metadata.name))
                #api_client.patch_node(node.metadata.name, taint_patch)
            if node.spec.taints != None:
                for taint in node.spec.taints:
                    logging.info("Adding tolerations for taint: {}".format(taint))
                    if (taint.value != "windows"):
                        keys.add((taint.key, taint.effect))
    except Exception as e:
        logging.info(e)
    # logging.info("Deploying daemonset...")
    # logging.info(utils.create_from_yaml(kclient, "/tmp/defender.yaml"))
    #logging.info(ret)

    return keys

def aws_cli_deploy_daemonset(api_client, kclient, debug_mode: bool):
    """
    Get cluster configurations from AWS EKS

    Args:
        client: AWS EKS client
        cluster_name: AWS Cluster Name

    Raises:
        ex: Client Error

    Returns:
        object: EKS Cluster
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
        
    logging.info("Running CLI commands")

    try:
        logging.info("Creating Twistlock namespace...")
        ret = api_client.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name="twistlock")))
        logging.info(ret)
    except Exception as e:
        logging.info(e)
    logging.info("Deploying daemonset...")
    logging.info(utils.create_from_yaml(kclient, "/tmp/defender.yaml"))
    #logging.info(ret)

    return "Successful Deployment"

def aws_sts_assume_role(client, assumed_role_arn, debug_mode: bool):
    """
    Assume role for Kubernetes Admin

    Args:
        client: AWS STS client
        assumed_role_arn: Role ARN

    Raises:
        ex: Client Error

    Returns:
        object: EKS Cluster
    """
    if debug_mode:
        logging.debug(
            "API READ_REQUEST \u2713: sending the request through."
        )
        
    logging.info("Assuming role...")
    try:
        response = client.assume_role(
            RoleArn=assumed_role_arn, 
            RoleSessionName="D@D",
            DurationSeconds=900,
            )
    except Exception as e:
        logging.info(e)

    return response["Credentials"]