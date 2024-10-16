# pylint: disable=import-error, wrong-import-position, no-name-in-module, relative-beyond-top-level, line-too-long
"""
Helper file to abstract Prisma code configurations from scripts.
"""
import os
import ast
import json
import logging
import datetime
from typing import Tuple, Any
from time import sleep
from implementation_functions.prisma_implementation_functions import (
    prisma_cspm_login,
    prisma_cwp_login,
    prisma_get_expired_serverless_defenders,
    prisma_get_serverless_defender_zip,
    prisma_check_image_in_registry,
    prisma_generate_protected_task,
    prisma_get_latest_version,
    prisma_get_undefended_eks_clusters,
    prisma_generate_daemonset
)


class Prisma():
    """
    This class contains initial configurations for Prisma.
    """

    def __init__(
        self,
        local_run: bool,
        request_offset=50,
        request_limit=50,
        cspm_token=None,
        cwp_token=None,
        tenant_id=None,
        debug_mode=None,
    ):
        if local_run:  # check if ran in a cloud env
            pass
        self._td_removed_attributes = [
            "taskDefinitionArn", 
            "revision",
            "status",
            "requiresAttributes",
            "compatibilities",
            "registeredAt",
            "registeredBy"
        ]
        self._cspm_token = cspm_token
        self._cwp_token = cwp_token
        self._tenant_id = tenant_id
        # if "AWS_LAMBDA_RUNTIME_API" not in os.environ:
        # self._cspm_endpoint = os.environ.get("CSPM_ENDPOINT")
        # self._cwp_endpoint = os.environ.get("CWP_ENDPOINT")
        # self._console_addr = os.environ.get("CONSOLE_ADDRESS")
        # self._prisma_access_key = os.environ.get("ACCESS_KEY")
        # self._prisma_secret_key = os.environ.get("SECRET_KEY")
        # # else:
        self._cspm_endpoint = "api2.prismacloud.io"
        self._cwp_endpoint = "us-east1.cloud.twistlock.com/us-2-158320372/api/v32.05"
        self._console_addr = "us-east1.cloud.twistlock.com"
        self._prisma_access_key = "4f32c7d8-3354-49ed-a1a7-03c7d4cc3b2d"
        self._prisma_secret_key = "nuOBXTek6MGvveOzfw05p+TqiZo="
        self._fargate_params = {
            "consoleaddr": self._console_addr,
            "cloudFormation": False,
            "filesystemMonitoring": False,
            "interpreter": "",
            "extractEntrypoint": "",
            "registryType": "aws",
            "registryCredentialID": "",
            "defenderImage": "",
            "defenderImagePullSecret": ""
        }
        self._debug_mode = debug_mode
        self._request_offset = request_offset
        self._request_limit = request_limit
    ################################################################################
    # region member props
    ################################################################################

    @property
    def cspm_endpoint(self):
        """
        cspm_endpoint member property

        Returns:
        str: cspm_endpoint
        """
        return self._cspm_endpoint

    @cspm_endpoint.setter
    def cspm_endpoint(self, cspm_endpoint):
        self._cspm_endpoint = cspm_endpoint

    @property
    def cwp_endpoint(self):
        """
        cwp_endpoint member property

        Returns:
        str: cwp_endpoint
        """
        return self._cwp_endpoint

    @cwp_endpoint.setter
    def cwp_endpoint(self, cwp_endpoint):
        self._cwp_endpoint = cwp_endpoint

    @property
    def updated_fargate_bundle(self):
        """
        updated_fargate_bundle member property

        Returns:
        str: updated_fargate_bundle
        """
        return self._updated_fargate_bundle

    @updated_fargate_bundle.setter
    def updated_fargate_bundle(self, updated_fargate_bundle):
        self._updated_fargate_bundle = updated_fargate_bundle

    @property
    def updated_fargate_image(self):
        """
        updated_fargate_image member property

        Returns:
        str: updated_fargate_image
        """
        return self._updated_fargate_image

    @updated_fargate_image.setter
    def updated_fargate_image(self, updated_fargate_image):
        self._updated_fargate_image = updated_fargate_image

    @property
    def prisma_access_key(self):
        """
        prisma_access_key member property

        Returns:
        str: prisma_access_key
        """
        return self._prisma_access_key

    @prisma_access_key.setter
    def prisma_access_key(self, prisma_access_key):
        self._prisma_access_key = prisma_access_key

    @property
    def prisma_secret_key(self):
        """
        prisma_secret_key member property

        Returns:
        str: prisma_secret_key
        """
        return self._prisma_secret_key

    @prisma_secret_key.setter
    def prisma_secret_key(self, prisma_secret_key):
        self._prisma_secret_key = prisma_secret_key

    @property
    def request_offset(self):
        """
        request_offset member property

        Returns:
        int: request_offset
        """
        return self._request_offset

    @request_offset.setter
    def request_offset(self, request_offset):
        self._request_offset = request_offset

    @property
    def request_limit(self):
        """
        request_limit member property

        Returns:
        int: request_limit
        """
        return self._request_limit

    @request_limit.setter
    def request_limit(self, request_limit):
        self._request_limit = request_limit

    @property
    def debug_mode(self):
        """
        debug_mode member property

        Returns:
        bool: debug_mode
        """
        return self._debug_mode

    @debug_mode.setter
    def debug_mode(self, debug_mode):
        self._debug_mode = debug_mode

    @property
    def cspm_token(self):
        """
        cspm_token member property

        Returns:
        bool: cspm_token
        """
        return self._cspm_token

    @cspm_token.setter
    def cspm_token(self, cspm_token):
        self._cspm_token = cspm_token

    @property
    def fargate_params(self):
        """
        fargate_params member property

        Returns:
        bool: fargate_params
        """
        return self._fargate_params

    @fargate_params.setter
    def fargate_params(self, fargate_params):
        self._fargate_params = fargate_params

    @property
    def cwp_token(self):
        """
        cwp_token member property

        Returns:
        bool: cwp_token
        """
        return self._cwp_token

    @cwp_token.setter
    def cwp_token(self, cwp_token):
        self._cwp_token = cwp_token

    @property
    def tenant_id(self):
        """
        tenant_id member property

        Returns:
        bool: tenant_id
        """
        return self._tenant_id

    @tenant_id.setter
    def tenant_id(self, tenant_id):
        self._tenant_id = tenant_id

    @property
    def latest_cwp_version(self):
        """
        latest_cwp_version member property

        Returns:
        bool: latest_cwp_version
        """
        return self._latest_cwp_version

    @latest_cwp_version.setter
    def latest_cwp_version(self, latest_cwp_version):
        self._latest_cwp_version = latest_cwp_version
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

    def send_api_request(self, prisma_api: Tuple[Any, int]) -> Tuple[Any, int]:
        """
        Send API requests to Prisma with error handling

        Args:
            prisma_api (Callable[..., Tuple[Any, int]]): Prisma API

        Returns:
            Any: api response
        """
        while True:
            response, status_code = prisma_api

            if status_code == 401:
                logging.info(
                    "Prisma API token expired... Generating a new one.")

                self.get_new_token()

                continue
            elif status_code == 200:
                logging.info(
                    "API success!"
                )

                return response, status_code
            elif status_code == 999:  # debug is enabled
                return None, status_code
            else:
                logging.info(
                    "Unexpected - Prisma API returned %s: %s", status_code, response)

                return response, status_code

    def get_cspm_token(self):
        """
        refresh the member token property
        """
        response = prisma_cspm_login(
            access_key=self._prisma_access_key,
            secret_key=self._prisma_secret_key,
            cspm_endpoint=self._cspm_endpoint,
            debug_mode=self._debug_mode,
        )

        self.cspm_token = response[0]["token"]
        self.tenant_id = response[0]["customerNames"][0]["prismaId"]

    def get_cwp_token(self):
        """
        refresh the member token property
        """
        response = prisma_cwp_login(
            access_key=self._prisma_access_key,
            secret_key=self._prisma_secret_key,
            cwp_endpoint=self._cwp_endpoint,
            debug_mode=self._debug_mode,
        )

        self._cwp_token = response[0]["token"]
    
    def get_expired_serverless_defenders(self):
        """
        get all expired serverless defenders
        """
        while True:
            response, status_code = prisma_get_expired_serverless_defenders(
                token=self.cwp_token,
                cwp_endpoint=self._cwp_endpoint,
                debug_mode=self._debug_mode,
            )
            
            if status_code == 401:
                print(
                    "Prisma API token expired... Generating a new one.")

                self.get_cwp_token()

                continue
            elif status_code != 200:
                print(
                    "Unexpected - Prisma API returned %s", status_code)

                return None

            break

        logging.info("Expired Defenders successfully retrieved.")

        return response
    
    def get_undefended_eks_clusters(self, region):
        """
        get all undefended eks cluster
        """
        while True:
            response, status_code = prisma_get_undefended_eks_clusters(
                token=self.cwp_token,
                region=region,
                cwp_endpoint=self._cwp_endpoint,
                debug_mode=self._debug_mode,
            )
            
            if status_code == 401:
                print(
                    "Prisma API token expired... Generating a new one.")

                self.get_cwp_token()

                continue
            elif status_code != 200:
                print(
                    "Unexpected - Prisma API returned %s", status_code)

                return None

            break

        logging.info("All undefended clusters successfully retrieved.")

        return response
    
    def get_serverless_defenders_zip(self, runtime):
        """
        refresh the member token property
        """
        while True:
            response, status_code = prisma_get_serverless_defender_zip(
                runtime,
                token=self.cwp_token,
                cwp_endpoint=self._cwp_endpoint,
                debug_mode=self._debug_mode,
            )
            
            if status_code == 401:
                print(
                    "Prisma API token expired... Generating a new one.")

                self.get_cwp_token()

                continue
            elif status_code != 200:
                print(
                    "Unexpected - Prisma API returned %s", status_code)

                return None

            break

        logging.info("Serverless Defender Zip downloaded.")

        return response

    def check_image_in_registry(self, image):
        """
        refresh the member token property
        """
        while True:
            response, status_code = prisma_check_image_in_registry(
                image,
                token=self.cwp_token,
                cwp_endpoint=self._cwp_endpoint,
                debug_mode=self._debug_mode,
            )
        
            if status_code == 401:
                print(
                    "Prisma API token expired... Generating a new one.")

                self.get_cwp_token()

                continue
            elif status_code != 200:
                print(
                    "Unexpected - Prisma API returned %s", status_code)

                return None

            break

        logging.info("Serverless Defender Zip downloaded.")

        return response

    def generate_protected_task(self, params, task_definition):
        """
        refresh the member token property
        """
        while True:
            response, status_code = prisma_generate_protected_task(
                params,
                task_definition,
                token=self.cwp_token,
                cwp_endpoint=self._cwp_endpoint,
                debug_mode=self._debug_mode,
            )
        
            if status_code == 401:
                print(
                    "Prisma API token expired... Generating a new one.")

                self.get_cwp_token()

                continue
            elif status_code != 200:
                print(
                    "Unexpected - Prisma API returned %s", status_code)

                return None

            break

        logging.info("Protected Task Generated.")

        return response

    def get_latest_version(self):
        """
        get the latest cwp version
        """
        while True:
            response, status_code = prisma_get_latest_version(
                token=self._cwp_token,
                cwp_endpoint=self._cwp_endpoint,
                debug_mode=self._debug_mode,
            )
        
            if status_code == 401:
                print(
                    "Prisma API token expired... Generating a new one.")

                self.get_cwp_token()

                continue
            elif status_code != 200:
                print(
                    "Unexpected - Prisma API returned %s", status_code)

                return None

            break

        logging.info(f"Latest Version {response} retrieved.")

        self._latest_cwp_version = response

    def generate_daemonset(self, cluster_name, tolerations):
        """
        get the latest cwp version
        """
        while True:
            response, status_code = prisma_generate_daemonset(
                cluster_name=cluster_name,
                PCS_URL=self._console_addr,
                token=self._cwp_token,
                cwp_endpoint=self._cwp_endpoint,
                debug_mode=self._debug_mode,
            )
        
            if status_code == 401:
                print(
                    "Prisma API token expired... Generating a new one.")

                self.get_cwp_token()

                continue
            elif status_code != 200:
                print(
                    "Unexpected - Prisma API returned %s", status_code)

                return None

            break

        logging.info(f"Daemonset Generated.")

        lines = response.split("\n")
        #Write Defender YAML to temp file for deployment
        f = open("/tmp/defender.yaml", "w")
        if len(tolerations) == 0:
            for line in lines:
                f.writelines(line)
                f.writelines("\n")
        else:
            for line in lines:
                if "memory: \"512Mi\"" in line:
                    line = line.replace("memory: \"512Mi\"", "memory: \"640Mi\"")
                    f.writelines(line)
                    f.writelines("\n")
                elif "containers:" in line:
                    logging.info("All taints recorded for {}: {}".format(cluster_name, tolerations))
                    if len(tolerations) != 0:
                        f.writelines("      tolerations:\n")
                        for key in tolerations:
                            f.writelines("      - key: \"{}\"\n".format(key[0]))
                            f.writelines("        operator: \"Exists\"\n")
                            f.writelines("        effect: \"{}\"\n".format(key[1]))
                    f.writelines(line)
                    f.writelines("\n")
                else:
                    f.writelines(line)
                    f.writelines("\n")
        f.close()
        logging.info("Daemonset written to /tmp/defender.yaml")
        return response

    def set_updated_fargate_image_and_bundle(self):
        with open('configurations/default_taskdef.json', 'r') as file:
            data = file.read()
        task_definition_template = json.loads(data)
        updated_defended_task_definition = self.generate_protected_task(self._fargate_params, json.dumps(task_definition_template))
        for object in updated_defended_task_definition["containerDefinitions"][1]["environment"]:
            if object["name"] == "INSTALL_BUNDLE":
                self.updated_fargate_bundle = object["value"]
        self._updated_fargate_image = updated_defended_task_definition["containerDefinitions"][1]["image"]
        logging.info("Set updated fargate image and bundle for expired defenders.")
    ################################################################################
    # endregion member functions
    ################################################################################
