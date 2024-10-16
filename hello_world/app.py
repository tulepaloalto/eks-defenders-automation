# pylint: disable=wrong-import-position
"""
TODO: update docstring

This script is triggered on a predefined basis to check and rotate Prisma Access Keys
    in AWS Secrets Manager.
    
It performs the following tasks:
    1. Grab Automation Access Keys for Prisma access from AWS Secrets Manager
    2. Grab existing Access Keys in Prisma Cloud
    Iterate over Access Keys and check the date created.
        If expired,
            Check if 2 keys already exist (keys are in buffer)
                If 2 keys exist,
                    Delete the old key if it has reached the expiration + buffer period.
                If 1 key exists,
                    Create a new key and update the value in Secrets Manager
                    A buffer period will be activated before removal of the old keys.
        If not expired,
            Do nothing.

Prerequisites:
    - Please ensure that you have configured the necessary environment variables 
        and service account credentials/permissions for the automation to work.
    - The Role attached to the Lambda function will need to be provisioned access
        to Secrets Manager for read/write capabilities.

Notes:

"""
import os
import sys
import logging
import datetime as dt
import json
sys.path.append(".")  # nopep8
from configurations.code import Configurations
from configurations.prisma import Prisma
from configurations.aws import AWS


if "AWS_LAMBDA_RUNTIME_API" in os.environ:
    LOCAL = False
else:
    LOCAL = True


def lambda_handler(event="", context=""):
    """
    TODO: docstring

    Args:
        context (LambdaContext, optional): 
            runtime environment and execution context of the Lambda function.
            Defaults to "".
    """
    ################################################################################
    # region init
    ################################################################################
    code_conf = Configurations(
        local_run=LOCAL,
        status_code=0,
        task="Initializing code configurations",
        status_text="",
    )
    prisma_conf = Prisma(
        local_run=LOCAL,
        request_offset=0,
        request_limit=50,
        debug_mode=code_conf.debug_mode
    )
    aws_conf = AWS(local_run=LOCAL, debug_mode=code_conf.debug_mode)
    ################################################################################
    # endregion init
    ################################################################################
    ################################################################################
    # region biz logic
    ################################################################################
    ################################################################################
    # region get prisma secrets
    ################################################################################
    # # prisma_keys = aws_conf.get_prisma_secrets()
    # prisma_conf.prisma_access_key = prisma_keys["prisma_access_key"]
    # prisma_conf.prisma_secret_key = prisma_keys["prisma_secret_key"]
    # prisma_conf.prisma_access_key = prisma_conf._prisma_access_key
    # prisma_conf.prisma_secret_key = prisma_conf._prisma_secret_key
    prisma_conf.get_cspm_token()
    prisma_conf.get_cwp_token()
    # Loop through each cluster and get services and task definitions
    # Get list of clusters
    clusters = prisma_conf.get_undefended_eks_clusters(aws_conf._aws_region)
    # clusters = aws_conf.list_clusters()
    logging.info(aws_conf._cluster_list)
    if aws_conf._cluster_list != []:
        # for cluster in clusters:
        cluster = {
            "name": "tuan_public_cluster"
        }
        logging.info(cluster["name"])
        if cluster["name"] in aws_conf._cluster_list:
            cluster_conf = aws_conf.describe_cluster(cluster["name"])
            aws_conf.create_access_entry(cluster["name"])
            api_client, kclient = aws_conf.initiate_kubernetes_api_client(cluster_conf)
            tolerations = aws_conf.taint_nodes(api_client, kclient)
            logging.info(tolerations)
            prisma_conf.generate_daemonset(cluster["name"], tolerations)
            aws_conf.deploy_daemonset(api_client, kclient)
            logging.info("Deployment completed for cluster {}".format(cluster["name"]))
    else:
        for cluster in clusters:
            cluster_conf = aws_conf.describe_cluster(cluster["name"])
            aws_conf.create_access_entry(cluster["name"])
            api_client, kclient = aws_conf.initiate_kubernetes_api_client(cluster_conf)
            prisma_conf.generate_daemonset(cluster["name"])
            aws_conf.deploy_daemonset(api_client, kclient)
            logging.info("Deployment completed for cluster {}".format(cluster["name"]))
    ################################################################################
    # endregion get prisma secrets
    ################################################################################
    ################################################################################
    # endregion biz logic
    ################################################################################

    return "Script finished running."

