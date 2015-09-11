# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from minion.plugins.base import BlockingPlugin

import logging
import json
import M2Crypto
import requests
import ssl
import time
import uuid


class SSLManagerPlugin(BlockingPlugin):
    PLUGIN_NAME = "SSL Manager"
    PLUGIN_VERSION = "0.0.1"

    API_PATH = "http://127.0.0.1:8383"
    NETWORK_GROUP = "NetworkIPv4"
    NETWORK_PLAN = "NetworkIPv4"

    INTERNAL_PKI = ["france"]

    target_CIDR = []

    functional_ip_list = []
    failed_ip_list = []

    internal_certified_hostname = []
    external_certified_hostname = []

    internal_group = ""
    internal_plan = ""

    external_group = ""
    external_plan = ""

    bare_ip_group = ""
    bare_ip_plan = ""

    # Instantiation of output
    report_dir = "/tmp/artifacts/"
    output_id = str(uuid.uuid4())
    schedule_stdout = ""
    schedule_stderr = ""
    logger = ""
    logger_path = report_dir + "logging_" + output_id + ".txt"


    def do_run(self):
        # TODO handle l'absence de valeur
        # Get the path to save output
        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']
            self.logger_path = self.report_dir + "logging_" + self.output_id + ".txt"

        # Get the array of names of private CA
        if "internal_pki" in self.configuration:
            self.INTERNAL_PKI = self.configuration.get('internal_pki')

        # Get the name of the plan and plan used for network scans
        if "network_group" in self.configuration and "network_plan" in self.configuration:
            self.NETWORK_GROUP = self.configuration.get('network_group')
            self.NETWORK_PLAN = self.configuration.get('network_plan')

        # Get the name of the group and plan used for external ssl scans
        if "external_group" in self.configuration and "external_plan" in self.configuration:
            self.external_group = self.configuration.get('external_group')
            self.external_plan = self.configuration.get('external_plan')

        # Get the name of the group and plan used for internal ssl scans
        if "internal_group" in self.configuration and "internal_plan" in self.configuration:
            self.internal_group = self.configuration.get('internal_group')
            self.internal_plan = self.configuration.get('internal_plan')

        # Get the name of the group and plan used for ip ssl scans
        if "bare_ip_group" in self.configuration and "bare_ip_plan" in self.configuration:
            self.bare_ip_group = self.configuration.get('bare_ip_group')
            self.bare_ip_plan = self.configuration.get('bare_ip_plan')

        # TODO remove and add failure to mandatory options
        # Get the array of groups to run (mandatory)
        if False:
            self.schedule_stderr += "No group is specified for the scheduled run\n"
            self.schedule_stderr += "This option is mandatory, and the group need to be valid.\n"
            self._save_artifacts()

            failure = {
                "hostname": "Utils plugins",
                "exception": self.schedule_stderr,
                "message": "Plugin Failed : missing email"
            }
            self._finish_with_failure(failure)

        # create logger
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

        # create console handler and set level to debug
        ch = logging.FileHandler(self.logger_path)
        ch.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        logger.addHandler(ch)

        # 'application' code
        logger.debug('debug message')
        logger.info('info message')
        logger.warn('warn message')
        logger.error('error message')
        logger.critical('critical message')

        # find open services
        self.get_open_tls()

        # Split services according certificate origin
        self.triage_targets()

        # Import into Minion
        if self.internal_group and self.internal_plan:
            self.set_minion_sites(self.API_PATH, self.internal_certified_hostname,
                                  self.internal_plan, self.internal_group)
        if self.external_group and self.external_plan:
            self.set_minion_sites(self.API_PATH, self.external_certified_hostname,
                                  self.external_plan, self.external_group)
        if self.bare_ip_group and self.bare_ip_plan:
            self.set_minion_sites(self.API_PATH, self.functional_ip_list,
                                  self.bare_ip_plan, self.bare_ip_group)

        self.schedule_stdout += "Import over\n"

        self.schedule_stdout += 'During scan, found  %d internal hostname and %d external hostname for %d ip\n' % \
                                (len(self.internal_certified_hostname), len(self.external_certified_hostname),
                                 len(self.functional_ip_list))

        self._save_artifacts()

    def set_minion_sites(self, api, sites, plans, groups):
        """ Set sites in Minion

        Set the sites given into Minion
        Log a warning if an error occurred like the site already exists

        Parameters
        ----------
        api : string
            Url of the backend of Minion
        sites :

        plans :

        groups :

        """

        for site in sites:
            s = {
                'url': site,
                'plans': [plans],
                'groups': [groups],
                'verification': {'enabled': False, 'value': None}
            }

            res = requests.get(api + '/sites', params={'url': site})

            res_json = res.json()
            if res_json['success'] and res_json['sites']:
                self.schedule_stdout += ('The site : %s already exists, we update it\n' % site)

                site_id = res_json['sites'][0]['id']
                s['plans'] = list(set(s['plans']) | set(res_json['sites'][0]['plans']))
                s['groups'] = list(set(s['groups']) | set(res_json['sites'][0]['groups']))

                res = requests.post(api + '/sites/' + site_id,
                                    headers={'content-type': 'application/json'},
                                    data=json.dumps(s))

                if res.json()['success']:
                    self.schedule_stdout += 'updated site : %s\n' % site
                else:
                    self.schedule_stderr += 'error while updating site %s : %s\n' % (site, res.json()['reason'])

            else:
                res = requests.post(api + '/sites',
                                    headers={'content-type': 'application/json'},
                                    data=json.dumps(s))
                if res.json()['success']:
                    self.schedule_stdout += 'created site : %s\n' % site
                else:
                    self.schedule_stderr += 'error while creating site %s : %s\n' % (site, res.json()['reason'])
            pass

    def get_names(self, ip):
        names = []
        # Get certificate
        try:
            cert = ssl.get_server_certificate((ip, 443), ssl_version=ssl.PROTOCOL_TLSv1)
        except ssl.SSLError as e:
            self.schedule_stderr += 'error while connecting to %s : %s\n' % (ip, e.strerror)

            self.failed_ip_list.append((ip, e.strerror))
            return "Failed", []

        x509 = M2Crypto.X509.load_cert_string(cert)

        # Get the CommonName
        # Code from M2Crypto test sample
        for entry in x509.get_subject().get_entries_by_nid(M2Crypto.m2.NID_commonName):
            common_name = entry.get_data().as_text()

            names.append(common_name)

        # Retrieve SubjectAltNames
        try:
            sans = x509.get_ext('subjectAltName').get_value()

            # Remove extension prefix and trailing space
            sans = sans.replace(" DNS:", "")
            sans = sans.replace("DNS:", "")

            san_list = sans.split(',')

            names.extend(san_list)
        except LookupError:
            # No SAN found
            pass

        # Get the name of the certificate issuer
        organization = x509.get_issuer().O

        return organization, names

    def get_open_tls(self):
        # Get list of network
        # Retrieve every target for every group
        try:
            r = requests.get(self.API_PATH + "/groups/" + self.NETWORK_GROUP)
            r.raise_for_status()
        except Exception as e:
            self.schedule_stderr += e.message
            self._save_artifacts()
            failure = {
                "hostname": "Utils plugins",
                "exception": e.message,
                "message": "Plugin failed"
            }
            self._finish_with_failure(failure)

        # Check the request is successful
        success = r.json()["success"]
        if not success:
            raise Exception("Could not retrieve info about group " + self.NETWORK_GROUP +
                            " because " + r.json()["reason"])

        self.target_CIDR = r.json()["group"]['sites']

        # Browse each network
        for network in self.target_CIDR:
            # Sleep to not DOS the API
            time.sleep(1)

            # Get plans associated to the target
            try:
                r = requests.get(self.API_PATH + "/sites?url=" + network)
                r.raise_for_status()
                target_id = r.json()['sites'][0]["id"]
            except Exception as e:
                self.schedule_stderr += e.message + "\n"
                continue

            # Get the status of the last scan
            params = {'site_id': target_id, 'plan_name': self.NETWORK_PLAN, 'limit': 1}

            # Sleep to not DOS the API
            time.sleep(1)
            try:
                r = requests.get(self.API_PATH + "/scans", params=params)
                r.raise_for_status()
            except Exception as e:
                self.schedule_stderr += e.message + "\n"
                continue

            j = r.json()

            # Check the request has results
            if not j.get('success'):
                msg = str("Can't get the last scan for the site %s and plan %s, reason : %s\n" %
                          (network, self.NETWORK_PLAN, j.get('reason')))
                self.schedule_stderr += msg

                continue

            # Get info about last scan
            last_scan = j.get("scans")

            # Retrieve the scan id
            if last_scan:
                scan_id = last_scan[0]["id"]
            else:
                # No scan found
                continue

            # Get issues of the scan
            # Sleep to not DOS the API
            time.sleep(1)
            try:
                r = requests.get(self.API_PATH + "/scans/" + scan_id)
                r.raise_for_status()
            except Exception as e:
                self.schedule_stderr += e.message + "\n"
                continue

            j = r.json()

            # Check the request has results
            if not j.get('success'):
                msg = str("Can't get the scan for the site %s and plan %s with id %s, reason : %s\n" %
                          (network, self.NETWORK_PLAN, scan_id, j.get('reason')))
                self.schedule_stderr += msg

                continue

            # Get the issues
            scan_issues = j["scan"]["sessions"][0]["issues"]

            # Search open 443 port
            for issue in scan_issues:
                if "443/tcp" in issue["Summary"]:
                    ip = issue["URLs"][0]["URL"]

                    # Add ip to task list
                    self.functional_ip_list.append(ip)
                    self.schedule_stdout += 'found %s responding to 443/tcp\n' % ip

    def triage_targets(self):
        # Browse each target
        for target in self.functional_ip_list:
            organization, url_list = self.get_names(target)

            # Check success TODO use exception
            if organization == "Failed":
                continue

            # Add missing https prefix
            url_list = ["https://" + s for s in url_list]

            # Check if the list is certified by corporate
            for corpo in self.INTERNAL_PKI:
                if corpo in organization.lower():
                    self.internal_certified_hostname.extend(url_list)
                else:
                    self.external_certified_hostname.extend(url_list)

        # Remove extra entries
        self.internal_certified_hostname = list(set(self.internal_certified_hostname))
        self.external_certified_hostname = list(set(self.external_certified_hostname))

    # Function used to save output of the plugin
    def _save_artifacts(self):
        stdout_log = self.report_dir + "STDOUT_" + self.output_id + ".txt"
        stderr_log = self.report_dir + "STDERR_" + self.output_id + ".txt"
        output_artifacts = []

        if self.schedule_stdout:
            with open(stdout_log, 'w+') as f:
                f.write(self.schedule_stdout)
            output_artifacts.append(stdout_log)
        if self.schedule_stderr:
            with open(stderr_log, 'w+') as f:
                f.write(self.schedule_stderr)
            output_artifacts.append(stderr_log)

        output_artifacts.append(self.logger_path)

        if output_artifacts:
            self.report_artifacts("SSL Manager Output", output_artifacts)

    def do_stop(self):
        # Save artifacts
        self._save_artifacts()

        # Call parent method
        BlockingPlugin.do_stop(self)
