##
# cycode_project_stats
# purpose is to pull repository stats from cycode and populate each repository with extra metadata (project name, ..) and repository metadata
#
# Authors: Wes MacKay, Eric Dapp
##

import requests
import sys
import logging
import time
import json
import os
import csv
import datetime
from collections import defaultdict

headers = {}

def get_token(client_id, client_secret):
    # print('client id and secret: ' +client_id+' '+client_secret) #debug Uncomment to see client id and secret
    print('Retrieving JWT Token...')
    token = ''

    auth_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    contents = {"clientId": client_id, "secret": client_secret}
    contents = json.dumps(contents)
    r = requests.post(f"https://{cycode_api_url}/api/v1/auth/api-token", data=contents, headers=auth_headers, timeout=3*60)
    response = r.json()
    if r.status_code == 200:
        token = response['token']
        print("New JWT token was obtained.")
        # print(f'response: {response}') # debug Uncomment to see token in response
    else:
        logging.info("New JWT token could not be obtained. Exiting...")
        sys.exit(1)
    return token

DATA_PASSWORD="${ENV_VAR}"

gitlabtoken="glpat-_g7Mq9tszQxzBs2SsHLV"

def assign_token():
     return os.environ['CYCODE_TOKEN']


def refresh_headers():
    headers['Authorization'] = "Bearer " + get_token(os.environ['CYCODE_CLIENT_ID'], os.environ['CYCODE_CLIENT_SECRET'])


# create RIG query using query_file and download report (different than v2 APIs)
def create_rig_report(query_file):
    # API Structure
    '''
    [
        {
            "scm_repository_scm_provider": "AzureDevopsCloud",
            "scm_repository_name": "vulnerableapp",
            "scm_repository_is_private": true,
            "scm_repository_language": "",
            "scm_repository_is_fork": false,
            "scm_repository_id": "cda387c6-8324-4cc5-81f2-5f19147f7be7::6a115ceb-324e-4475-b2f5-e5b1e57d048c",
            "scm_repository_is_scm_archived": false
        }
    ]
    '''

    # --------------------------------
    #  Create Standalone report
    # --------------------------------

    print("Creating Standalone report")
    url = f"https://{cycode_api_url}/report/api/v2/report/standalone-execute"
    # query is a filename
    if ".json" in query_file:
        # get data for query from file
        with open(query_file, 'r') as file:
            query = json.load(file)
    # query contents should be passed directly
    else:
        query = query_file

    # create report
    response = requests.post(url, headers=headers, json=query)

    # get report id
    report_id = response.json().get('id')
    print(f" - Report ID: {report_id}")

    # get executiuon id
    execution_id = response.json().get('report_executions')[0].get('id')

    # --------------------------------
    #  Report Status
    # --------------------------------

    response = requests.get(url, headers=headers)
    url = f"https://{cycode_api_url}/report/api/v2/report/executions?executions_ids[0]={execution_id}&include_orphan_executions=true"

    status = 'Pending'
    report_path = ''

    while (status != 'Completed'):
        response = requests.get(url, headers=headers)
        # print(f" - Response: {response.json()}")
        status = response.json()[0].get('status')
        if status == 'Failed':
            print('Report failed')
            print(response.json())
            sys.exit(1)
        print(f" - - Report status: {status}")
        time.sleep(40)

    report_path = response.json()[0].get('storage_details').get('path')

    # --------------------------------
    #  Download Report
    # --------------------------------

    print('Downloading report')
    url = f"https://{cycode_api_url}/files/api/v1/file/reports/{report_path}"
    response = requests.get(url, headers=headers)
    return response.json()


# generic function to download api data (v2 api calls) using url_template and limit as parameters
def download_api_data(url_template, limit):
    index = 1
    raw_list = []
    # format URL with index and limit
    url = url_template.format(cycode_url=cycode_url, index=index, limit=limit)
    # run API call
    response = requests.get(url, headers=headers, timeout=3*60)

    ## check response and exit
    if response.status_code != 200:
        print("Failed, exiting")
        print(response.status_code)
        sys.exit(response.status_code)

    ## go through all pages to retrieve full list
    assets = response.json()
    raw_list = response.json()['data']
    print("reading page %s with total: %s" % (index, len(assets["data"])))
    while assets['data']:
        index += 1
        url = url_template.format(cycode_url=cycode_url, index=index, limit=limit)
        response = requests.get(url, headers=headers, timeout=3*60)
        assets = response.json()
        raw_list.extend(response.json()['data'])
        print("reading page %s with total: %s" % (index, len(assets["data"])))

    return raw_list


# download REPO stats from Violations page
def download_repo_stats(url):
    limit = 1                       # normally this is 1000, but since we're only capturing the total severity count, we only need the 1st page
    raw_list = []

    ### API Structure (raw_list) ###
    '''
    [
        {
            "repositoryId": "R_kgDOK7f6fQ",
            "repositoryName": "repo-name",
            "visibility": "Private",
            "organizationName": "org-name",
            "organizationId": "O_kgFOBs6hdg",
            "createdAtString": "2024-03-28T13:14:31.198Z",
            "labels": [
                "Private",
                "app-proxy"
            ],
            "scmCreated": "2023-12-18T20:37:34+00:00",
            "provider": "Github",
            "vulnerablePackages": [],
            "lastDetection": "2024-05-28T19:15:31.198Z",
            "severityGrouping": {
                "Critical": 530,
                "High": 3,
                "Medium": 1,
                "Low": 0,
                "Info": 0
            },
            "externalIntegrationTypes": [],
            "total": 534
        }
    ]
    '''
    '''
    ### DEBUG ###
    with open("output/ford-debug/raw_repo_stats_20240530_085840.json", 'r') as file:
        raw_list = json.load(file)
    ### DEBUG ###
    '''
    # download_data from api with limit included
    raw_list = download_api_data(url, limit)

    ### DEBUG ###
    write_json_file(raw_list, "raw_repo_stats") if debug_flag == "yes" else None

    # COMBINE raw_list into REPOSITORIES
    for asset in raw_list:
        repo_id = asset["repositoryId"]
        # reformat severityGrouping into their own "severity" keys (critical, high, medium, low)
        for key, value in asset['severityGrouping'].items():
            REPOSITORIES[repo_id][key.lower()] = asset["severityGrouping"][key]
        REPOSITORIES[repo_id]["total"] = asset["total"]
        # ----------- below repos are not in RIG but in Violations page -----------
        # if repos below are not (internal or personal) repos, LABEL them with "PHANTOM_REPO"
        # this could be due to migration, will investigate
        if REPOSITORIES[repo_id]["repoName"] == "":
            REPOSITORIES[repo_id]["repoName"] = asset["repositoryName"]
            REPOSITORIES[repo_id]["repoID"] = repo_id
            REPOSITORIES[repo_id]["org"] = asset["organizationName"]
            REPOSITORIES[repo_id]["labels"] = ["PHANTOM_REPO"]

    print("## Completed Download of REPO STATS ##")
    return


# download PROJECT stats from Violations page
def download_project_stats():
    limit = 1000
    raw_list = []

    ### API Structure (raw_list)
    '''
    [
        {
            "id": 17139,
            "name": "project-name",
            "description": "",
            "business_impact": "High",
            "is_archived": false,
            "created": "2024-05-27T18:22:59.168115+00:00",
            "modified": "2024-05-27T18:25:59.168115+00:00",
            "created_by": "931d46b3-0e5e-4fc2-8534-915ad7ce8817",
            "tenant_id": "ee7872ab-a58c-4a79-8485-a48d06b790e6",
            "members": [
                {
                    "member_id": "3fc22e2d-c8b0-4dca-8fd8-4a982aaf3de9",
                    "email": "person1@gmail.com"
                },
                {
                    "member_id": "cfbe3056-ecb2-49b2-af3c-7aeec643d4c0",
                    "email": "person2@gmail.com"
                }
            ]
    ]
    '''
    '''
    ### DEBUG ###
    with open("output/ford-debug/raw_project_stats_20240529_183637.json", 'r') as file:
        raw_list = json.load(file)
    ### DEBUG ###
    '''
    # create url template so we can iterate index using download_api_data()
    url = "https://app.cycode.com/api/project?limit={limit}&excludeViolations=true&pageIndex={index}"
    # download_data from api with limit included
    raw_list = download_api_data(url, limit)

    ### DEBUG ###
    write_json_file(raw_list, "raw_project_stats") if debug_flag == "yes" else None

    # COMBINE raw_list into PROJECTS
    # asset = project object
    for asset in raw_list:
        project_id = asset["id"]
        project_name = asset["name"]
        # store only Project_Managers email
        pm_email_list = []
        for list in asset["project_managers"]:
            for key, value in list.items():
                if key == "email":
                    pm_email_list.append(value)
        # create PROJECTS entry (do this now if the Project has no repos/projectManagers/open severity counts)
        PROJECTS[project_id]["projectName"] = project_name
        PROJECTS[project_id]["projectID"] = project_id
        PROJECTS[project_id]["projectManager"] = pm_email_list

    print("## Completed Download of PROJECT STATS ##")
    return


# download REPO_METADATA
# download repo metadata with orgs, labels, personal_repos & fork status from multiple reports
def download_repo_metadata():
    '''
    ### DEBUG ###
    with open("output/ford-debug/raw-repos-with-orgs-metadata_20240530_085214.json", 'r') as file:
        raw_repos_with_orgs = json.load(file)
    with open("output/ford-debug/raw-repo-with-lables-metadata_20240530_085214.json", 'r') as file:
        raw_repos_with_labels = json.load(file)
    with open("output/ford-debug/raw-personal-repos-metadata_20240530_111813.json", 'r') as file:
        raw_personal_repos = json.load(file)
    ### DEBUG ###
    '''
    # create RIG Report and download raw data from 3 reports
    print("\n# REPOS with ORGS")
    raw_repos_with_orgs = create_rig_report("query-repo-org.json")
    print("\n# REPOS with LABELS")
    raw_repos_with_labels = create_rig_report("query-label-repo.json")
    print("\n# Personal REPOS")
    raw_personal_repos = create_rig_report("query-personal-repo.json")

    ### DEBUG ###
    write_json_file(raw_repos_with_orgs, "raw-repos-with-orgs-metadata") if debug_flag == "yes" else None
    write_json_file(raw_repos_with_labels, "raw-repos-with-lables-metadata") if debug_flag == "yes" else None
    write_json_file(raw_personal_repos, "raw-personal-repos-metadata") if debug_flag == "yes" else None

    # COMBINE REPOS_WITH_ORGS with REPOSITORIES
    for asset in raw_repos_with_orgs:
        repo_id = asset["scm_repository_id"]
        org_id = asset["scm_organization_id"]
        # Add REPOS metadata to the REPOSTORIES structure to use later
        REPOSITORIES[repo_id]["repoName"] = asset["scm_repository_name"]
        REPOSITORIES[repo_id]["repoID"] = repo_id
        REPOSITORIES[repo_id]["fork"] = asset["scm_repository_is_fork"]
        REPOSITORIES[repo_id]["org"] = asset["scm_organization_name"]
        # Add ORGS + REPOS to the ORGS structure to use later
        ORGS[org_id]["orgID"] = org_id
        ORGS[org_id]["orgName"] = asset["scm_organization_name"]
        ORGS[org_id]["repos"][repo_id] = asset["scm_repository_name"]

    # COMBINE REPOS_WITH_LABELS with REPOSITORIES
    for asset in raw_repos_with_labels:
        repo_id = asset["scm_repository_id"]
        REPOSITORIES[repo_id]["labels"].append(asset["label_label_name"])

    # COMBINE PERSONAL_REPOS with REPOSITORIES
    # these are personal repos (not internal) that cycode has detected (this list is with/out violations)
    # LABEL these repos with "PERSONAL_REPOSITORY"
    for asset in raw_personal_repos:
        repo_id = asset["scm_member_public_repository_id"]
        REPOSITORIES[repo_id]["repoName"] = asset["scm_member_public_repository_name"]
        REPOSITORIES[repo_id]["repoID"] = repo_id
        REPOSITORIES[repo_id]["fork"] = asset["scm_member_public_repository_is_fork"]
        REPOSITORIES[repo_id]["labels"] = ["PERSONAL_REPOSITORY"]

    return


# write data to filename as JSON file
def write_json_file(data, filename):
    if filename == "":
        filename = "report_output"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'output/{filename}_{timestamp}.json'
    with open(filename, 'w') as file:
        file.write(json.dumps(data))


# write REPOSITORIES to filename as CSV file
# this function is highly customized to the structure of REPOSITORIES
# you should write another function if you want a simple write data to csv file
def write_csv_file(data, filename):
    #def createFile(violations, projectCount):
    #print("\n### Creating CSV file ###")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # open csv file
    csv_file = open(f"output/{filename}_{timestamp}.csv", "w", newline="")
    # create csv writer object
    csv_writer = csv.writer(csv_file)

    # write headers
    csv_writer.writerow(
        [
            "Project Name",
            "Project ID",
            "Repo Name",
            "Repo ID",
            "Organization",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info",
            "Total",
            "Project Manager",
            "Fork",
            "Labels"
        ]
    )
    # write each row with repo details
    counter = 0
    for repo_id, repo in data.items():
        counter += 1
        # repo has 1 or more projects assigned
        if repo.get("projectID") != []:
            # if a repo has multiple projects, write out each project as separate line
            for project_id in repo["projectID"]:
                # write out each repo as a csv row
                csv_writer.writerow(
                    [
                        repo["projectName"][project_id],
                        project_id,
                        repo["repoName"],
                        repo["repoID"],
                        repo["org"],
                        repo["critical"],
                        repo["high"],
                        repo["medium"],
                        repo["low"],
                        repo["info"],
                        repo["total"],
                        "; ".join(map(str, repo["projectManager"][project_id])),
                        repo["fork"],
                        "; ".join(map(str, repo["labels"]))
                    ]
                )
        # repo has no project assigned
        else:
            # write out each repo as a csv row
            csv_writer.writerow(
                [
                    "",
                    "",
                    repo["repoName"],
                    repo["repoID"],
                    repo["org"],
                    repo["critical"],
                    repo["high"],
                    repo["medium"],
                    repo["low"],
                    repo["info"],
                    repo["total"],
                    "",
                    repo["fork"],
                    "; ".join(map(str, repo["labels"]))
                ]
            )

    csv_file.close()


# Find key, value from list
def find_key_in_list(list, key, value):
    for i, dict in enumerate(list):
        if dict[key] == value:
            return i
    return None


if __name__ == '__main__':
    limit = 1000
    # check if a command line argument was provided
    # cycode_repo_stats.py [--debug, cycode_url]
    cycode_url = "app.cycode.com"
    if len(sys.argv) > 1:
        # if --debug flag is provided, we will output more files for debugging
        if sys.argv[1] == "--debug":
            debug_flag = "yes"
        # options that can be passed ["app.cycode.com", "app.eu.cycode.com"]
        elif "cycode.com" in sys.argv[1]:
            cycode_url = sys.argv[1]
            print("Found Cycode URL")
        else:
            print("Please include flag \"--debug\" or argument \"app.eu.cycode.com\"")
            exit(0)
    # no arguments passed
    else:
        debug_flag = "no"
    cycode_api_url = "api." + cycode_url.split('.',1)[1]

    token = get_token(os.environ['CYCODE_CLIENT_ID'], os.environ['CYCODE_CLIENT_SECRET'])
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + token
    }

    password = "0+rfumaQJh8p+ViUGaBTeCgimS2ukgGnKrLQI911"

    # REPOSITORIES structure that we will add all reports into
    REPOSITORIES = defaultdict(
        lambda: {
                "repoName": "",
                "repoID": "",
                "org": "",
                "labels": [],
                "fork": "",
                "projectName": {},
                "projectID": [],
                "projectManager": {},
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0
        }
    )

    # ORG structure to hold organization, org id, and repo name/id so we can add project data to org repositories
    ORGS = defaultdict(
        lambda: {
                "orgName": "",
                "orgID": "",
                "repos": {}
        }
    )

    # PROJECTS structure that we will add all reports into
    PROJECTS = defaultdict(
        lambda: {
                "projectName": "",
                "projectID": "",
                "projectManager": [],
                "repositories": {},
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0
        }
    )

    # New Agenda
    # (1) download projects --> create projects structure
    # (1.1) look for orgs/repos from projects (need to implement teams/labels later)
    # (2) search repo_stats url for secrets & sca/sast/iac separately

    # (1) Get all PROJECT stats from Cycode
    print("\n## Downloading PROJECT STATS ##")
    download_project_stats()

    # (2) now we need to get the Total Severity Counts for SAST/SCA/IAC & Secrets separately
    # iterate through each Violations page with the project field added and SAST/SCA/IAC as filters
    # iterate through with secrets only
    url = "https://{cycode_url}/api/violations/v2/repository-violations?f0=list%2Cstatus&limit={limit}&f0=Open&policyType=SecretDetection&pageIndex={index}"
    download_repo_stats(url)
    # iterate through with SAST/SCA/IAC only
    url = "https://{cycode_url}/api/violations/v2/repository-violations?f0=list%2Ccategory&f0=SAST&f0=SCA&f0=IaC&f1=list%2Cstatus&f1=Open&limit={limit}&pageIndex={index}"
    download_repo_stats(url)

    # (4) write FINAL contents of REPO Stats
    write_json_file(REPOSITORIES, "FINAL_repo_stats")
    write_csv_file(REPOSITORIES, "FINAL_repo_stats")

    # (5) script DONE, write out to user conditions of the script
    print("\nCYCODE REPO STATS has FINISHED.  We have created 2 files (1x JSON, 1x CSV)  \nThis will show all internal & personal REPOS tied to your account.")
