# pylint: disable=too-many-lines, import-error, line-too-long
"""
TODO: update docstring
This file contains a collection of Prisma helper functions for automating tasks.

Functions:
- prisma_cspm_login(access_key, secret_key, cspm_endpoint, debug_mode)


Usage:
- Simply import this file and call the function. For example:

    from prisma_implementation_functions import prisma_cspm_login

Notes:
- Before using these functions, be sure to configure the .env appropriately.

"""
import json
import logging
from typing import Tuple, Any
import requests


def prisma_cspm_login(
    access_key: str,
    secret_key: str,
    cspm_endpoint: str,
    debug_mode=False,
) -> Tuple[Any, int]:
    """
    Generate the token for Prisma CSPM API access.

    In debug mode,
        this API call will be made as it is a read-only request.

    Parameters:
        access_key (str): Prisma generated access key
        secret_key (str): Prisma generated secret key
        cspm_endpoint (str): Cloud Security Posture Management API endpoint
        debug_mode (bool): Debug enabled or disabled

    Returns:
        Tuple[dict, int]:
            dict: login response
            int: response status code
    """
    endpoint = f"https://{cspm_endpoint}/login"

    logging.info("Generating Prisma token using endpoint: %s", endpoint)

    if debug_mode:
        logging.info(
            "API READ_REQUEST \u2713: sending the request through."
        )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }

    body = {"username": access_key, "password": secret_key}

    response = requests.post(
        endpoint, headers=headers, json=body, timeout=360
    )

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        logging.info("Prisma API returned Status Code: %s",
                     response.status_code)

        return None, response.status_code

def prisma_cwp_login(
    access_key: str,
    secret_key: str,
    cwp_endpoint: str,
    debug_mode=False,
) -> Tuple[Any, int]:
    """
    Generate the token for Prisma CWP API access.

    In debug mode,
        this API call will be made as it is a read-only request.

    Parameters:
        access_key (str): Prisma generated access key
        secret_key (str): Prisma generated secret key
        cwp_endpoint (str): Cloud Security Posture Management API endpoint
        debug_mode (bool): Debug enabled or disabled

    Returns:
        Tuple[dict, int]:
            dict: login response
            int: response status code
    """
    endpoint = f"https://{cwp_endpoint}/authenticate"

    logging.info("Generating Prisma token using endpoint: %s", endpoint)

    if debug_mode:
        logging.info(
            "API READ_REQUEST \u2713: sending the request through."
        )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }

    body = {"username": access_key, "password": secret_key}

    response = requests.post(
        endpoint, headers=headers, json=body, timeout=360
    )

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        logging.info("Prisma API returned Status Code: %s",
                     response.status_code)

        return None, response.status_code

def prisma_get_expired_serverless_defenders(
    token: str, cwp_endpoint: str, debug_mode=False
) -> Tuple[Any, int]:
    """
    Returns all expired serverless defenders if you have a Prisma Cloud System Admin role. 

    https://pan.dev/prisma-cloud/api/cwpp/get-defenders/

    In debug mode,
        this API call will be made as it is a read-only request.

    Parameters:
        token (str): Prisma token for authentication
        cwp_endpoint (str): Runtime Security Management API endpoint
        debug_mode (bool): Debug enabled or disabled

    Returns:
        list: expired serverless defenders

    """
    endpoint = f"https://{cwp_endpoint}/defenders?type=serverless&latest=true"

    logging.info("Getting expired defenders from: %s", endpoint)

    if debug_mode:
        logging.info(
            "API READ_REQUEST \u2713: sending the request through."
        )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": "Bearer "+ token,
    }

    response = requests.get(
        endpoint, headers=headers, timeout=60
    )

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, response.status_code
    else:
        logging.info(
            "Prisma API returned: %s - %s", response.status_code, response.text
        )

        return None, response.status_code

def prisma_get_undefended_eks_clusters(
    token: str, region, cwp_endpoint: str, debug_mode=False
) -> Tuple[Any, int]:
    """
    Returns all undefended clusters if you have a Prisma Cloud System Admin role. 

    https://pan.dev/prisma-cloud/api/cwpp/get-cloud-discovery/

    In debug mode,
        this API call will be made as it is a read-only request.

    Parameters:
        token (str): Prisma token for authentication
        cwp_endpoint (str): Runtime Security Management API endpoint
        debug_mode (bool): Debug enabled or disabled

    Returns:
        list: undefended eks clusters

    """
    endpoint = f"https://{cwp_endpoint}/cloud/discovery/entities?region={region}&serviceType=aws-eks&limit=10&offset="

    logging.info("Getting undefended eks clusters from: %s", endpoint)

    if debug_mode:
        logging.info(
            "API READ_REQUEST \u2713: sending the request through."
        )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": "Bearer "+ token,
    }
    clusters = []
    no_more_clusters = False
    initial_offset=0
    offset=10
    
    while (no_more_clusters==False):
        response = requests.get(
            endpoint+str(initial_offset), headers=headers, timeout=60
        )

        if response.status_code == 200:
            data = json.loads(response.content)
            for cluster in data:
                if cluster["defended"] == False:
                    clusters.append(cluster)

            if len(data) < offset:
                logging.info(
                    "Retrieved the last {} clusters. Retrieved {} clusters in total".format(len(data), len(clusters))
                )
                return clusters, response.status_code
            else:
                logging.info(
                    "Retrieved {} clusters - Getting next {}...".format(offset, offset)
                )
                initial_offset+=offset
        else:
            logging.info(
                "Prisma API returned: %s - %s", response.status_code, response.text
            )

            return None, response.status_code

def prisma_get_serverless_defender_zip(
    runtime: str, token: str, cwp_endpoint: str, debug_mode=False
) -> Tuple[Any, int]:
    """
    Returns serverless defender zip if you have a Prisma Cloud System Admin role. 

    https://pan.dev/prisma-cloud/api/cwpp/get-defenders/

    In debug mode,
        this API call will be made as it is a read-only request.

    Parameters:
        token (str): Prisma token for authentication
        cwp_endpoint (str): Runtime Security Management API endpoint
        debug_mode (bool): Debug enabled or disabled

    Returns:
        serverless defender zip

    """
    endpoint = f"https://{cwp_endpoint}/defenders/serverless/bundle"

    logging.info("Getting serverless defender zip from: %s", endpoint)

    if debug_mode:
        logging.info(
            "API READ_REQUEST \u2713: sending the request through."
        )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "Content-Type": "application/octet-stream",
        "Authorization": "Bearer "+ token,
    }

    data = '{{"provider": "aws", "runtime": "{}"}}'.format((runtime))

    response = requests.post(
        endpoint, headers=headers, data=data, timeout=60
    )

    if response.status_code == 200:
        return response.content, response.status_code
    else:
        logging.info(
            "Prisma API returned: %s - %s", response.status_code, response.text
        )

        return None, response.status_code

def prisma_add_access_key(
    token: str, cspm_endpoint: str, payload: dict, debug_mode=False
) -> Tuple[Any, int]:
    """
    Adds a new access key for the current user. If you have API access, you can create up to two access keys.

    If you want to create an access key for an existing Prisma Cloud service account instead of for the current user, 
        then specify the name of the existing service account as the value 
        for the request body parameter serviceAccountName.

    https://pan.dev/prisma-cloud/api/cspm/add-access-keys/

    In debug mode,
        this API call will not be made as it is a create request.


    Parameters:
        token (str): Prisma token for authentication
        cspm_endpoint (str): Cloud Security Posture Management API endpoint
        payload (dict): payload
        debug_mode (bool): Debug enabled or disabled

    Returns:
        list: api response

    """
    endpoint = f"https://{cspm_endpoint}/access_keys"

    logging.info("Creating access key, %s using %s",
                 payload['name'], endpoint)

    if debug_mode:
        logging.info(
            "API CREATE_REQUEST \u2717: mocking the response.")

        return None, 999

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    response = requests.post(
        endpoint, headers=headers, json=payload, timeout=60
    )

    if response.status_code == 200:
        return response, response.status_code
    else:
        return response.text, response.status_code

def prisma_check_image_in_registry(
    image, token: str, cwp_endpoint: str, debug_mode=False
) -> Tuple[Any, int]:
    """
    Return true in task_definitions image is in registry scan
    
    https://pan.dev/prisma-cloud/api/cwpp/get-registry/

    In debug mode,
        this API call will be made as it is a read-only request.

    Parameters:
        token (str): Prisma token for authentication
        cwp_endpoint (str): Runtime Security Management API endpoint
        debug_mode (bool): Debug enabled or disabled

    Returns:
        list: expired serverless defenders

    """
    endpoint = f"https://{cwp_endpoint}/registry?compact=true&search={image}"

    logging.info("Checking if image exist in registry with %s", endpoint)

    if debug_mode:
        logging.info(
            "API READ_REQUEST \u2713: sending the request through."
        )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": "Bearer "+ token,
    }

    response = requests.get(
        endpoint, headers=headers, timeout=60
    )

    if response.status_code == 200:
        if response.text:
            return True, response.status_code
        else:
            return False, response.status_code
    else:
        logging.info(
            "Prisma API returned: %s - %s", response.status_code, response.text
        )

        return None, response.status_code

def prisma_generate_protected_task(
    params, task_definition, token: str, cwp_endpoint: str, debug_mode=False
):
    """
    Generate protected task definiton
    
    https://pan.dev/prisma-cloud/api/cwpp/post-defenders-fargate-json/

    In debug mode,
        this API call will be made as it is a read-only request.

    Parameters:
        token (str): Prisma token for authentication
        cwp_endpoint (str): Runtime Security Management API endpoint
        debug_mode (boolean): Debug enabled or disabled
        params: filter cluster
        task_definition (str): Unprotected task definition

    Returns:
        status_code

    """
    endpoint = f"https://{cwp_endpoint}/defenders/fargate.json"

    logging.info("Checking if image exist in registry with %s", endpoint)

    if debug_mode:
        logging.info(
            "API READ_REQUEST \u2713: sending the request through."
        )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": "Bearer "+ token,
    }

    response = requests.post(
        endpoint, headers=headers, data=task_definition, params=params, timeout=60
    )

    if response.status_code == 200:
        return json.loads(response.text), response.status_code
    else:
        logging.info(
            "Prisma API returned: %s - %s", response.status_code, response.text
        )

        return None, response.status_code

def prisma_get_latest_version(
    token: str,
    cwp_endpoint: str,
    debug_mode=False,
) -> str:
    """
    Get the latest version for the cwp api
    """
    endpoint = f"https://{cwp_endpoint}/version"

    logging.info("Generating Prisma token using endpoint: %s", endpoint)

    if debug_mode:
        logging.info(
            "API READ_REQUEST \u2713: sending the request through."
        )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": "Bearer "+ token,
    }


    response = requests.get(
        endpoint, headers=headers, timeout=360
    )

    if response.status_code == 200:
        data = response.text.replace(".", "_").strip('"\\')

        return data, 200
    else:
        logging.info("Prisma API returned Status Code: %s",
                     response.status_code)

        return None, response.status_code
    
def prisma_generate_daemonset(
    cluster_name, PCS_URL, token: str, cwp_endpoint: str, debug_mode=False
):
    """
    Generate protected task definiton
    
    https://pan.dev/prisma-cloud/api/cwpp/post-defenders-fargate-json/

    In debug mode,
        this API call will be made as it is a read-only request.

    Parameters:
        token (str): Prisma token for authentication
        cwp_endpoint (str): Runtime Security Management API endpoint
        debug_mode (boolean): Debug enabled or disabled
        task_definition (str): Unprotected task definition

    Returns:
        status_code

    """
    endpoint = f"https://{cwp_endpoint}/defenders/daemonset.yaml"

    logging.info("Generating daemonset with %s", endpoint)

    if debug_mode:
        logging.info(
            "API READ_REQUEST \u2713: sending the request through."
        )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": "Bearer "+ token,
    }
    cluster_data = '{{"cluster": "{}","containerRuntime": "crio","orchestration": "kubernetes","namespace": "twistlock","uniqueHostname": true,"consoleAddr":"{}"}}'.format(cluster_name, PCS_URL)
    response = requests.post(
        endpoint, headers=headers, data=cluster_data,
    )

    if response.status_code == 200:
        return response.text, response.status_code
    else:
        logging.info(
            "Prisma API returned: %s - %s", response.status_code, response.text
        )

        return None, response.status_code