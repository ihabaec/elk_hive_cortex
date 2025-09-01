#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests
import urllib
import urllib.error
import json
import datetime

class MSDefenderEndpoints(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.msdefenderTenantId = self.get_param('config.tenantId', None, 'TenantId missing!')
        self.msdefenderAppId = self.get_param('config.appId', None, 'AppId missing!')
        self.msdefenderSecret = self.get_param('config.appSecret', None, 'AppSecret missing!')
        self.msdefenderResourceAppIdUri = self.get_param('config.resourceAppIdUri', None, 'resourceAppIdUri missing!')
        self.msdefenderOAuthUri = self.get_param('config.oAuthUri', None, 'oAuthUri missing!')

        self.observable = self.get_param('data.data', None, "Data is empty")
        self.observableType = self.get_param('data.dataType', None, "Data type is empty")
        self.caseId = self.get_param("data.case.caseId", None, "caseId is missing")
        self.caseTitle = self.get_param('data.case.title', None, 'Case title is missing').encode("utf-8")
        self.service = self.get_param("config.service", None, "Service Missing")

        self.msdefenderSession = requests.Session()
        self.msdefenderSession.headers.update(
            {
                'Accept' : 'application/json',
                'Content-Type' : 'application/json'
            }
        )

    def run(self):
        Responder.run(self)
        url = "{}/{}/oauth2/token".format(
            self.msdefenderOAuthUri,self.msdefenderTenantId
            )

        body = {
            'resource' : self.msdefenderResourceAppIdUri,
            'client_id' : self.msdefenderAppId,
            'client_secret' : self.msdefenderSecret,
            'grant_type' : 'client_credentials'
        }

        data = urllib.parse.urlencode(body).encode("utf-8")
        req = urllib.request.Request(url, data)

        try:
            response = urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            #print("message: HTTP ErrorCode {}. Reason: {}".format(e.code,e.reason))
            self.error({'message': "HTTP ErrorCode {}. Reason: {}".format(e.code,e.reason)})
        except urllib.error.URLError as e:
            #print("message: URL Error: {}".format(e.reason))
            self.error({'message': "URL Error: {}".format(e.reason)})

        jsonResponse = json.loads(response.read())
        token = jsonResponse["access_token"]

        self.msdefenderSession.headers.update(
            {
                'Authorization' : 'Bearer {0}'.format(token)
            }
        )

        def getMachineId(id):
            time = datetime.datetime.now() - datetime.timedelta(minutes=60)
            time = time.strftime("%Y-%m-%dT%H:%M:%SZ")

            if self.observableType == "ip":
                url = "https://api.securitycenter.windows.com/api/machines/findbyip(ip='{}',timestamp={})".format(id,time)
            else:
                url = "https://api.securitycenter.windows.com/api/machines?$filter=computerDnsName+eq+'{}'".format(id)

            try:
                response = self.msdefenderSession.get(url=url)
                if response.status_code == 200:
                    jsonResponse = response.json()
                    if len(response.content) > 100:
                        if jsonResponse["value"][0]["aadDeviceId"] is None:
                           return jsonResponse["value"][0]["id"]
                        return jsonResponse["value"][0]["aadDeviceId"]
                    else:
                        self.error({'message': "Can't get hostname from Microsoft API"})
            except requests.exceptions.RequestException as e:
                self.error({'message': e})

        def isolateMachine(machineId):
            '''
            example
            POST https://api.securitycenter.windows.com/api/machines/{id}/isolate
            '''
            url = 'https://api.securitycenter.windows.com/api/machines/{}/isolate'.format(machineId)

            body = {
                'Comment': 'Isolate machine due to TheHive case {}'.format(self.caseId),
                'IsolationType': 'Full'
                }

            try:
                response = self.msdefenderSession.post(url=url, json=body)
                if response.status_code == 201:
                    self.report({'message': "Isolated machine: " + self.observable })
                elif response.status_code == 400 and "ActiveRequestAlreadyExists" in response.content.decode("utf-8"):
                    self.report({'message': "Error isolating machine: ActiveRequestAlreadyExists"})
                else:
                    self.error({'message': "Can't isolate machine"})
            except requests.exceptions.RequestException as e:
                self.error({'message': e})

            self.report({'message': "Isolated machine: " + self.observable })

        def runFullVirusScan(machineId):
            '''
            example
            POST https://api.securitycenter.windows.com/api/machines/{id}/runAntiVirusScan
            '''
            url = 'https://api.securitycenter.windows.com/api/machines/{}/runAntiVirusScan'.format(machineId)

            body = {
                'Comment': 'Full scan to machine due to TheHive case {}'.format(self.caseId),
                'ScanType': 'Full'
                }

            try:
                response = self.msdefenderSession.post(url=url, json=body)
                if response.status_code == 201:
                    self.report({'message': "Started full VirusScan on machine: " + self.observable })
                elif response.status_code == 400 and "ActiveRequestAlreadyExists" in response.content.decode("utf-8"):
                    self.report({'message': "Error full VirusScan on machine: ActiveRequestAlreadyExists"})
                else:
                    self.error({'message': "Error full VirusScan on machine"})
            except requests.exceptions.RequestException as e:
                self.error({'message': e})


        def unisolateMachine(machineId):
            '''
            example
            POST https://api.securitycenter.windows.com/api/machines/{id}/unisolate
            '''
            url = 'https://api.securitycenter.windows.com/api/machines/{}/unisolate'.format(machineId)
            body = {
                'Comment': 'Unisolate machine due to TheHive case {}'.format(self.caseId)
                }

            try:
                response = self.msdefenderSession.post(url=url, json=body)
                if response.status_code == 201:
                    self.report({'message': "Unisolated machine: " + self.observable })
                elif response.status_code == 400 and "ActiveRequestAlreadyExists" in response.content.decode("utf-8"):
                    self.report({'message': "Error unisolating machine: ActiveRequestAlreadyExists"})
                else:
                    self.error({'message': "Can't unisolate machine"})
            except requests.exceptions.RequestException as e:
                self.error({'message': e})


        def restrictAppExecution(machineId):
            '''
            example
            POST https://api.securitycenter.windows.com/api/machines/{id}/restrictCodeExecution
            '''
            url = 'https://api.securitycenter.windows.com/api/machines/{}/restrictCodeExecution'.format(machineId)
            body = {
                'Comment': 'Restrict code execution due to TheHive case {}'.format(self.caseId)
                }

            try:
                response = self.msdefenderSession.post(url=url, json=body)
                if response.status_code == 201:
                    self.report({'message': "Restricted app execution on machine: " + self.observable })
                elif response.status_code == 400 and "ActiveRequestAlreadyExists" in response.content.decode("utf-8"):
                    self.report({'message': "Error restricting app execution on machine: ActiveRequestAlreadyExists"})
                else:
                    self.error({'message': "Can't restrict app execution"})
            except requests.exceptions.RequestException as e:
                self.error({'message': e})

        
        def unrestrictAppExecution(machineId):
            '''
            example
            POST https://api.securitycenter.windows.com/api/machines/{id}/unrestrictCodeExecution
            '''
            url = 'https://api.securitycenter.windows.com/api/machines/{}/unrestrictCodeExecution'.format(machineId)
            body = {
                'Comment': '"Remove code execution restriction since machine was cleaned and validated due to TheHive case {}'.format(self.caseId)
                }

            try:
                response = self.msdefenderSession.post(url=url, json=body)
                if response.status_code == 201:
                    self.report({'message': "Removed app execution restriction on machine: " + self.observable })
                elif response.status_code == 400 and "ActiveRequestAlreadyExists" in response.content.decode("utf-8"):
                    self.report({'message': "Error removing app execution restriction on machine: ActiveRequestAlreadyExists"})
                else:
                    self.error({'message': "Can't unrestrict app execution"})
            except requests.exceptions.RequestException as e:
                self.error({'message': e})

        
        def startAutoInvestigation(machineId):
            '''
            example
            POST https://api.securitycenter.windows.com/api/machines/{id}/startInvestigation
            '''
            url = 'https://api.securitycenter.windows.com/api/machines/{}/startInvestigation'.format(machineId)

            body = {
                'Comment': 'Start investigation due to TheHive case {}'.format(self.caseId)
                }

            try:
                response = self.msdefenderSession.post(url=url, json=body)
                if response.status_code == 201:
                    self.report({'message': "Started Auto Investigation on : " + self.observable })
                elif response.status_code == 400 and "ActiveRequestAlreadyExists" in response.content.decode("utf-8"):
                    self.report({'message': "Error lauching auto investigation on machine: ActiveRequestAlreadyExists"})
                else:
                    self.error({'message': "Error auto investigation on machine"})
            except requests.exceptions.RequestException as e:
                self.error({'message': e})


        def pushCustomIocAlert(observable):
            
            if self.observableType == 'ip':
                indicatorType = 'IpAddress'
            elif self.observableType == 'url':
                indicatorType = 'Url'
            elif self.observableType == 'domain':
                indicatorType = 'DomainName'
            elif self.observableType == 'hash':
                if len(observable) == 32:
                    indicatorType = 'FileMd5'
                elif len(observable) == 40:
                    indicatorType = 'FileSha1'
                elif len(observable) == 64:
                    indicatorType = 'FileSha256'
                else:
                    self.report({'message':"Observable is not a valid hash"})
            else:
                self.error({'message':"Observable type must be ip, url, domain or hash"})
            
            url = 'https://api.securitycenter.windows.com/api/indicators'
            body = {
                'indicatorValue': observable,
                'indicatorType': indicatorType,
                'action': 'Alert',
                'title': "TheHive IOC: {}".format(self.caseTitle),
                'severity': 'High',
                'description': "TheHive case: {} - caseId {}".format(self.caseTitle,self.caseId),
                'recommendedActions': 'N/A'
            }

            try:
                response = self.msdefenderSession.post(url=url, json=body)
                if response.status_code == 200:
                    self.report({'message': "Added IOC to Defender with Alert mode: " + self.observable })
            except requests.exceptions.RequestException as e:
                self.error({'message': e})

        def pushCustomIocBlock(observable):

            if self.observableType == 'ip':
                indicatorType = 'IpAddress'
            elif self.observableType == 'url':
                indicatorType = 'Url'
            elif self.observableType == 'domain':
                indicatorType = 'DomainName'
            elif self.observableType == 'hash':
                if len(observable) == 32:
                    indicatorType = 'FileMd5'
                elif len(observable) == 40:
                    indicatorType = 'FileSha1'
                elif len(observable) == 64:
                    indicatorType = 'FileSha256'
                else:
                    self.report({'message':"Observable is not a valid hash"})
            else:
                self.error({'message':"Observable type must be ip, url, domain or hash"})

            url = 'https://api.securitycenter.windows.com/api/indicators'
            body = {
                'indicatorValue' : observable,
                'indicatorType' : indicatorType,
                'action' : 'AlertAndBlock',
                'title' : "TheHive IOC: {}".format(self.caseTitle),
                'severity' : 'High',
                'description' : "TheHive case: {} - caseId {}".format(self.caseTitle,self.caseId),
                'recommendedActions' : 'N/A'
            }

            try:
                response = self.msdefenderSession.post(url=url, json=body)
                if response.status_code == 200:
                    self.report({'message': "Added IOC to Defender with Alert and Block mode: " + self.observable })
            except requests.exceptions.RequestException as e:
                self.error({'message': e})


        if self.service == "isolateMachine":
            isolateMachine(getMachineId(self.observable))
        elif self.service == "unisolateMachine":
            unisolateMachine(getMachineId(self.observable))
        elif self.service == "runFullVirusScan":
            runFullVirusScan(getMachineId(self.observable))
        elif self.service == "restrictAppExecution":
            restrictAppExecution(getMachineId(self.observable))
        elif self.service == "unrestrictAppExecution":
            unrestrictAppExecution(getMachineId(self.observable))
        elif self.service == "startAutoInvestigation":
            startAutoInvestigation(getMachineId(self.observable))
        elif self.service == "pushIOCBlock":
            pushCustomIocBlock(self.observable)
        elif self.service == "pushIOCAlert":
            pushCustomIocAlert(self.observable)
        else:
            self.error({'message': "Unidentified service"})

    def operations(self, raw):
        self.build_operation('AddTagToCase', tag='MSDefenderResponder:run')
        if self.service == "isolateMachine":
            return [self.build_operation("AddTagToArtifact", tag="MsDefender:isolated")]
        elif self.service == "runFullVirusScan":
            return [self.build_operation("AddTagToArtifact", tag="MsDefender:fullVirusScan")]
        elif self.service == "unisolateMachine":
            return [self.build_operation("AddTagToArtifact", tag="MsDefender:unIsolated")]
        elif self.service == "restrictAppExecution":
            return [self.build_operation("AddTagToArtifact", tag="MsDefender:restrictedAppExec")]
        elif self.service == "unrestrictAppExecution":
            return [self.build_operation("AddTagToArtifact", tag="MsDefender:unrestrictedAppExec")]

if __name__ == '__main__':
    
  MSDefenderEndpoints().run()
