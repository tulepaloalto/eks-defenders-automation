# pylint: disable=line-too-long
"""
Helper file to abstract AWS code configurations from scripts.
"""
import os
import json
import logging
from time import sleep
from implementation_functions.aws_implementation_functions import (
    aws_initiate_session,
    aws_initiate_secrets_manager_client,
    aws_initiate_lambda_client,
    aws_initiate_ecs_client,
    aws_ecs_update_service,
    aws_ecs_register_task_definition,
    aws_ecs_get_services,
    aws_lambda_get_function,
    aws_secrets_manager_get_secret,
    aws_secrets_manager_update_secret_value,
    aws_secrets_manager_create_secret,
    aws_lambda_get_layer,
    aws_lambda_publish_layer,
    aws_lambda_update_function,
    aws_ecs_get_clusters,
    aws_ecs_is_fargate_service,
    aws_ecs_get_service_desc,
    aws_ecs_get_fargate_defender_status,
    aws_initiate_eks_client,
    aws_eks_describe_cluster,
    aws_eks_list_clusters,
    aws_eks_update_kubeconfig,
    aws_initiate_sts_client,
    aws_eks_check_access_entry,
    aws_eks_create_access_entry,
    aws_sts_assume_role,
    aws_cli_deploy_daemonset,
    aws_initiate_kubernetes_api_client,
    aws_cli_taint_nodes
)


class AWS():
    """
    This class contains initial configurations for AWS.
    """

    def __init__(
        self,
        local_run: bool,
        debug_mode=None,
    ):
        # if local_run:
        #     self._aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
        #     self._aws_secret_access_key = os.environ.get(
        #         "AWS_SECRET_ACCESS_KEY")
        #     self._aws_session_token = os.environ.get("AWS_SESSION_TOKEN")
        self._local_run = local_run
        self._debug_mode = debug_mode
        # if "AWS_LAMBDA_RUNTIME_API" not in os.environ:
        # self._secret_name = os.environ.get("AWS_AUTOMATION_SECRET_NAME")
        # self._aws_region = os.environ.get("REGION")
        # self._role_arn = os.environ.get("AWS_ROLE_ARN")
        # self._access_policy_arn = os.environ.get("AWS_ACCESS_POLICY_ARN")
        # self._cluster_list = os.environ.get("CLUSTER_LIST")
        # else:
        self._secret_name = "Prisma-Automation-Secrets"
        self._aws_region = "us-east-2"
        self._role_arn = "arn:aws:iam::506350273566:role/service-role/eks_deployment-role-xho75jwg"
        self._access_policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
        self._cluster_list = ["tuan_public_cluster"]
        
        session = aws_initiate_session()
        self._secrets_client = aws_initiate_secrets_manager_client(
            session,
            region=self._aws_region
        )
        self._ecs_client= aws_initiate_ecs_client(
            session,
            region=self._aws_region
        )
        self._lambda_client= aws_initiate_lambda_client(
            session,
            region=self._aws_region
        )
        self._sts_client= aws_initiate_sts_client(
            session,
            region=self._aws_region
        )
        self._eks_client= aws_initiate_eks_client(
            session,
            region=self._aws_region
        )
        
    ################################################################################
    # region member props
    ################################################################################
    @property
    def secret_name(self):
        """
        secret_name member property

        Returns:
        str: secret_name
        """
        return self._secret_name

    @property
    def role_arn(self):
        """
        secret_name member property

        Returns:
        str: secret_name
        """
        return self._role_arn
    
    @property
    def cluster_list(self):
        """
        secret_name member property

        Returns:
        str: secret_name
        """
        return self._cluster_list
    
    @property
    def access_policy_arn(self):
        """
        secret_name member property

        Returns:
        str: secret_name
        """
        return self._access_policy_arn
    
    @property
    def secrets_client(self):
        """
        secrets_client member property

        Returns:
        AWS Secrets Manager client: secrets_client
        """
        return self._secrets_client
    
    @property
    def lambda_client(self):
        """
        secrets_client member property

        Returns:
        AWS Secrets Manager client: secrets_client
        """
        return self._lambda_client

    @property
    def sts_client(self):
        """
        secrets_client member property

        Returns:
        AWS Secrets Manager client: secrets_client
        """
        return self._sts_client

    @property
    def ecs_client(self):
        """
        secrets_client member property

        Returns:
        AWS Secrets Manager client: ecs_client
        """
        return self._ecs_client

    @property
    def eks_client(self):
        """
        secrets_client member property

        Returns:
        AWS Secrets Manager client: eks_client
        """
        return self._eks_client

    @property
    def aws_cli(self):
        """
        secrets_client member property

        Returns:
        AWS Secrets Manager client: eks_client
        """
        return self._aws_cli

    @property
    def aws_region(self):
        """
        aws_region member property

        Returns:
        str: aws_region
        """
        return self._aws_region

    @property
    def debug_mode(self):
        """
        debug_mode member property

        Returns:
        bool: debug_mode
        """
        return self._debug_mode

    @property
    def local_run(self):
        """
        local_run member property

        Returns:
        bool: local_run
        """
        return self._local_run
    ################################################################################
    # endregion member props
    ################################################################################

    ################################################################################
    # region member functions
    ################################################################################

    def log_and_pause(self, msg: str, *args, **kwargs) -> None:
        """
        TODO: docstring
        """
        logging.info(msg, *args, **kwargs)

        sleep(3)

    def initiate_kubernetes_api_client(self, cluster) -> dict:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        client = aws_initiate_kubernetes_api_client(
            cluster=cluster, debug_mode=self.debug_mode)

        return client

    def get_prisma_secrets(self) -> dict:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        secret_response = aws_secrets_manager_get_secret(
            client=self.secrets_client, secret_name=self.secret_name, debug_mode=self.debug_mode)

        prisma_keys = json.loads(json.loads(
            secret_response['SecretString'])["AWS_SECRETS"])

        return prisma_keys

    def get_ecs_clusters(self) -> list:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_ecs_get_clusters(
            client=self.ecs_client, debug_mode=self.debug_mode)

        return response

    def get_cluster_services(self, cluster_name) -> list:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_ecs_get_services(
            cluster_name, client=self.ecs_client, debug_mode=self.debug_mode)

        return response
    
    def get_service_desc(self, service_arn, cluster_name):
        """
        Get Service Description for a given ECS service
        """
        response = aws_ecs_get_service_desc(service_arn, cluster_name, client=self.ecs_client, debug_mode=self.debug_mode)
        
        return response

    def is_fargate_service(self, service_desc):
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        service, response = aws_ecs_is_fargate_service(
            service_desc, debug_mode=self.debug_mode)

        return service, response

    def get_fargate_defender_status(self, latest_version, task_definition_arn):
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        task_definition, response = aws_ecs_get_fargate_defender_status(
            latest_version, task_definition_arn, client=self.ecs_client, debug_mode=self.debug_mode)

        return task_definition, response
    
    def register_task_definition(self, task_definition) -> str:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_ecs_register_task_definition(
            task_definition, client=self.ecs_client, debug_mode=self.debug_mode)

        return response
    
    def update_service(self, cluster_name, service_name, task_definition) -> dict:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_ecs_update_service(
            cluster_name, service_name, task_definition, client=self.ecs_client, debug_mode=self.debug_mode)

        return response

    def get_function(self, function_name) -> dict:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_lambda_get_function(
            function_name, client=self.lambda_client, debug_mode=self.debug_mode)

        return response
    
    def update_function(self, function_name, layer_arn) -> dict:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_lambda_update_function(
            function_name, layer_arn, client=self.lambda_client, debug_mode=self.debug_mode)

        return response
    
    def get_layer(self, layer_arn) -> dict:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_lambda_get_layer(
            layer_arn, client=self.lambda_client, debug_mode=self.debug_mode)

        return response
    
    def describe_cluster(self, cluster_name) -> dict:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_eks_describe_cluster(
            cluster_name, client=self.eks_client, debug_mode=self.debug_mode)

        return response
    
    def list_clusters(self) -> dict:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_eks_list_clusters(
            client=self.eks_client, debug_mode=self.debug_mode)

        return response
    
    def check_access_entry(self, cluster_name):
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_eks_check_access_entry(
            client=self.eks_client, cluster_name=cluster_name, assumed_role_arn=self.role_arn, debug_mode=self.debug_mode)

        return response
    
    def create_access_entry(self, cluster_name):
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_eks_create_access_entry(
            client=self.eks_client, cluster_name=cluster_name, assumed_role_arn=self.role_arn, access_policy_arn=self.access_policy_arn, debug_mode=self.debug_mode)

        return response
    
    def assume_role(self):
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_sts_assume_role(
            client=self.sts_client, assumed_role_arn=self.role_arn, debug_mode=self.debug_mode)

        return response
    
    def publish_layer(self, layer_arn, zip_file, runtimes) -> dict:
        """
        Get Automation Access Keys for Prisma access from Secrets Manager.
        """
        response = aws_lambda_publish_layer(
            layer_arn, zip_file, runtimes, client=self.lambda_client, debug_mode=self.debug_mode)

        return response

    def rotate_secret(self, secret_name: str, secret_value: str) -> bool:
        """
        TODO: docstring
        """
        rotated = aws_secrets_manager_update_secret_value(
            client=self.secrets_client, secret_name=secret_name, secret_value=secret_value, debug_mode=self.debug_mode)

        if rotated:
            logging.info("Secret sucessfully rotated!")

        return rotated

    def create_secret(self, secret_name: str, secret_value: str) -> bool:
        """
        TODO: docstring
        """
        created = aws_secrets_manager_create_secret(
            client=self.secrets_client, secret_name=secret_name, secret_value=secret_value, debug_mode=self.debug_mode)

        if created:
            logging.info("Secret successfully created!")

        return created

    def rotate_keys(self, access_keys: list[dict]) -> None:

        """
        TODO: docstring

        Args:
            access_keys (list[dict]): _description_
        """
        self.log_and_pause(
            "Rotating %s keys from Prisma in AWS...", len(access_keys))

        for access_key in access_keys:
            rotated = self.rotate_secret(
                secret_name=access_key["name"], secret_value=access_key["value"])

            if not rotated:
                logging.info(
                    "Secret doesn't exist in AWS yet, creating it now.")
                created = self.create_secret(
                    secret_name=access_key["name"], secret_value=access_key["value"])

                if not created:
                    logging.info(
                        "Issue creating secret in AWS for `%s`...", access_key["name"])
                continue

            continue
    
    def update_kubeconfig(self, cluster: str) -> None: 
        """
        TODO: docstring

        Args:
            access_keys (list[dict]): _description_
        """
        response = aws_eks_update_kubeconfig(
            cluster=cluster, region=self._aws_region, debug_mode=self.debug_mode)

        return response
    
    def deploy_daemonset(self, api_client, kclient) -> None: 
        """
        TODO: docstring

        Args:
            access_keys (list[dict]): _description_
        """
        response = aws_cli_deploy_daemonset(
            api_client=api_client, kclient=kclient, debug_mode=self.debug_mode)

        return response
    
    def taint_nodes(self, api_client, kclient) -> None: 
        """
        TODO: docstring

        Args:
            access_keys (list[dict]): _description_
        """
        response = aws_cli_taint_nodes(
            api_client=api_client, kclient=kclient, debug_mode=self.debug_mode)

        return response
    ################################################################################
    # endregion member functions
    ################################################################################
